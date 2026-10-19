"""Closed provider-preflight diagnostics, without exception messages or payloads."""

from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Protocol, cast
from urllib.error import URLError

from botocore import exceptions as boto_errors  # type: ignore[import-untyped]
from lowerduckpond_m3_archive import storage

from scripts.cloudflare_read_diagnostics import EXCEPTIONS, MAX_CHAIN, MAX_CODE

FORMAT = "lowerduckpond-provider-preflight-failure-v1"
PHASES = frozenset({"inputs", "storage", "edge"})
MAX_ELAPSED = 7 * 24 * 60 * 60
MAX_SOURCE_LINE = 100000
TYPES = {
    **EXCEPTIONS,
    RuntimeError: "RuntimeError",
    ValueError: "ValueError",
    ExceptionGroup: "ExceptionGroup",
    BaseExceptionGroup: "BaseExceptionGroup",
    storage.ArchiveQualificationError: "ArchiveQualificationError",
    boto_errors.BotoCoreError: "BotoCoreError",
    boto_errors.ClientError: "ClientError",
    boto_errors.EndpointConnectionError: "EndpointConnectionError",
    boto_errors.ConnectTimeoutError: "ConnectTimeoutError",
    boto_errors.ReadTimeoutError: "ReadTimeoutError",
    boto_errors.ConnectionClosedError: "ConnectionClosedError",
    boto_errors.SSLError: "SSLError",
    boto_errors.HTTPClientError: "HTTPClientError",
}
# Only exact source-owned messages become reason labels. Unknown text is never
# copied, even for a familiar exception class or an unrecognized provider code.
STORAGE_REASONS = {
    "bucket versioning is not enabled": "versioning-not-enabled",
    "current objects exist inside the required empty boundary": "current-objects-present",
    "versions or delete markers exist inside the boundary": "versions-or-markers-present",
    "multipart uploads exist inside the boundary": "multipart-uploads-present",
    **{
        f"{kind} listing exceeded its {bound} bound": f"{kind}-listing-{bound}-bound"
        for kind in ("object", "version", "multipart")
        for bound in ("entry", "page")
    },
    "object listing repeated a continuation token": "object-pagination-repeated",
    "version listing repeated continuation markers": "version-pagination-repeated",
    "multipart listing repeated continuation markers": "multipart-pagination-repeated",
}
OPERATIONS = frozenset(
    {
        "GetBucketAcl",
        "GetObjectAcl",
        "GetBucketPolicy",
        "GetBucketLifecycleConfiguration",
        "GetBucketVersioning",
        "ListObjectsV2",
        "ListObjectVersions",
        "ListMultipartUploads",
    }
)
PROVIDER_CODES = frozenset(
    {
        "AccessDenied",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
        "ExpiredToken",
        "RequestTimeTooSkewed",
        "NoSuchBucket",
        "NoSuchBucketPolicy",
        "NoSuchLifecycleConfiguration",
        "SlowDown",
        "InternalError",
        "ServiceUnavailable",
    }
)
STORAGE_FUNCTIONS = frozenset(
    {
        "assert_storage_empty",
        "assert_versioning_enabled",
        "list_current_objects",
        "list_versions",
        "list_multipart_uploads",
        "_mapping_list",
        "_required_string",
        "_is_truncated",
        "_require_prefix",
    }
)


class _ClientFailure(Protocol):
    response: object
    operation_name: object


def _source(error: BaseException) -> dict[str, object] | None:
    selected = None
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        if (
            code.co_name in STORAGE_FUNCTIONS
            and Path(code.co_filename).resolve() == Path(storage.__file__).resolve()
        ):
            selected = {
                "file": "lowerduckpond_m3_archive/storage.py",
                "function": code.co_name,
                "line": trace.tb_lineno,
            }
        trace = trace.tb_next
    return selected


def _metadata(error: BaseException) -> dict[str, object]:
    if type(error) is not boto_errors.ClientError:
        return {}
    known = cast(_ClientFailure, error)
    response = known.response
    if type(response) is not dict:
        return {}
    result: dict[str, object] = {}
    metadata = response.get("ResponseMetadata")
    if type(metadata) is dict:
        status, retries = metadata.get("HTTPStatusCode"), metadata.get("RetryAttempts")
        if type(status) is int and 100 <= status <= 599:  # noqa: PLR2004 - HTTP status
            result["http_status"] = status
        if type(retries) is int and 0 <= retries <= 100:  # noqa: PLR2004 - bounded metadata
            result["sdk_retry_count"] = retries
    details = response.get("Error")
    if type(details) is dict and type(details.get("Code")) is str:
        result["provider_code"] = (
            details["Code"] if details["Code"] in PROVIDER_CODES else "unknown"
        )
    operation = known.operation_name
    result["operation"] = (
        operation if type(operation) is str and operation in OPERATIONS else "unknown"
    )
    return result


def exception_facts(error: BaseException) -> dict[str, object]:
    pending: list[tuple[BaseException, str, int | None]] = [(error, "root", None)]
    nodes: list[dict[str, object]] = []
    seen: set[int] = set()
    repeated = False
    omitted = False
    while pending and len(nodes) < MAX_CHAIN:
        current, relation, parent = pending.pop(0)
        if id(current) in seen:
            repeated = True
            continue
        seen.add(id(current))
        node: dict[str, object] = {
            "type": TYPES.get(type(current), "unknown"),
            "relation": relation,
            "parent": parent,
            **_metadata(current),
        }
        for name in ("errno", "verify_code"):
            value = getattr(current, name, None) if type(current) in EXCEPTIONS else None
            if type(value) is int and -MAX_CODE <= value <= MAX_CODE:
                node[name] = value
        if type(current) is storage.ArchiveQualificationError:
            args = current.args
            node["reason"] = (
                STORAGE_REASONS.get(args[0], "unclassified-storage-contract")
                if len(args) == 1 and type(args[0]) is str
                else "unclassified-storage-contract"
            )
        node["source"] = _source(current)
        index = len(nodes)
        nodes.append(node)
        linked: list[tuple[object, str]] = [
            (current.__cause__, "cause"),
            (current.__context__, "context"),
        ]
        if type(current) is URLError:
            linked.append((current.reason, "reason"))
        if type(current) in {ExceptionGroup, BaseExceptionGroup}:
            members = cast(BaseExceptionGroup[BaseException], current).exceptions
            linked.extend((child, "member") for child in members[:MAX_CHAIN])
            if len(members) > MAX_CHAIN:
                omitted = True
        if type(current) in TYPES and isinstance(current, boto_errors.BotoCoreError):
            # Botocore wraps connection errors here, often without __cause__.
            kwargs = current.kwargs
            if type(kwargs) is dict:
                linked.append((kwargs.get("error"), "transport"))
        for child, relationship in linked:
            if isinstance(child, BaseException):
                pending.append((child, relationship, index))
    return {"nodes": nodes, "truncated": bool(pending) or omitted, "repeated": repeated}


def document(error: BaseException, *, phase: str, started: float) -> dict[str, object]:
    elapsed = max(0.0, time.monotonic() - started)
    return {
        "format": FORMAT,
        "authority": "diagnostic-only",
        "phase": phase if phase in PHASES else "unknown",
        # Invocation count, not a guess at the number of requests or SDK retries.
        "invocation_attempt": 1,
        "elapsed_seconds": round(elapsed, 6) if math.isfinite(elapsed) else None,
        "exception_chain": exception_facts(error),
    }


def verified(raw: object) -> dict[str, object]:  # noqa: PLR0912 - closed diagnostic schema
    """Validate a helper's safe projection before copying it across the CLI boundary."""
    if (
        type(raw) is not dict
        or set(raw)
        != {
            "format",
            "authority",
            "phase",
            "invocation_attempt",
            "elapsed_seconds",
            "exception_chain",
        }
        or raw["format"] != FORMAT
        or raw["authority"] != "diagnostic-only"
        or type(raw["phase"]) is not str
        or raw["phase"] not in PHASES | {"unknown"}
        or type(raw["invocation_attempt"]) is not int
        or raw["invocation_attempt"] != 1
    ):
        raise ValueError("invalid provider diagnostic")
    elapsed = raw["elapsed_seconds"]
    if elapsed is not None and (
        type(elapsed) not in {int, float}
        or not 0 <= elapsed <= MAX_ELAPSED
        or not math.isfinite(elapsed)
    ):
        raise ValueError("invalid provider diagnostic duration")
    chain = raw["exception_chain"]
    if type(chain) is not dict or set(chain) != {"nodes", "truncated", "repeated"}:
        raise ValueError("invalid provider diagnostic chain")
    if type(chain["truncated"]) is not bool or type(chain["repeated"]) is not bool:
        raise ValueError("invalid provider diagnostic chain flags")
    nodes = chain["nodes"]
    if type(nodes) is not list or not 1 <= len(nodes) <= MAX_CHAIN:
        raise ValueError("invalid provider diagnostic chain bound")
    choices = {
        "type": set(TYPES.values()) | {"unknown"},
        "relation": {"root", "cause", "context", "transport", "reason", "member"},
        "reason": set(STORAGE_REASONS.values()) | {"unclassified-storage-contract"},
        "operation": OPERATIONS | {"unknown"},
        "provider_code": PROVIDER_CODES | {"unknown"},
    }
    numeric = {
        "errno": (-MAX_CODE, MAX_CODE),
        "verify_code": (-MAX_CODE, MAX_CODE),
        "http_status": (100, 599),
        "sdk_retry_count": (0, 100),
    }
    for index, node in enumerate(nodes):
        if (
            type(node) is not dict
            or not {"type", "relation", "parent", "source"} <= set(node)
            or not set(node) <= set(choices) | set(numeric) | {"parent", "source"}
        ):
            raise ValueError("invalid provider diagnostic node")
        for key, allowed in choices.items():
            if key in node and (type(node[key]) is not str or node[key] not in allowed):
                raise ValueError("invalid provider diagnostic label")
        for key, (lower, upper) in numeric.items():
            if key in node and (type(node[key]) is not int or not lower <= node[key] <= upper):
                raise ValueError("invalid provider diagnostic number")
        if (index == 0 and (node["parent"] is not None or node["relation"] != "root")) or (
            index > 0 and (type(node["parent"]) is not int or not 0 <= node["parent"] < index)
        ):
            raise ValueError("invalid provider diagnostic relationship")
        source = node["source"]
        if source is not None and (
            type(source) is not dict
            or set(source) != {"file", "function", "line"}
            or source["file"] != "lowerduckpond_m3_archive/storage.py"
            or type(source["function"]) is not str
            or source["function"] not in STORAGE_FUNCTIONS
            or type(source["line"]) is not int
            or not 1 <= source["line"] <= MAX_SOURCE_LINE
        ):
            raise ValueError("invalid provider diagnostic source")
    return cast(dict[str, object], raw)


class StorageReadinessError(RuntimeError):
    """A bound read-only readiness failure; never permission to allocate an attempt."""

    def __init__(self, diagnostic: object) -> None:
        self.diagnostic = verified(diagnostic)
        super().__init__("reused lease whole-bucket storage readiness failed")
