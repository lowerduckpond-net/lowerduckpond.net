"""Pinned Python-library qualification probes."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Mapping
from importlib.metadata import version
from typing import Final

import botocore.session  # type: ignore[import-untyped]
import rfc8785
from hypothesis import given, settings, strategies
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]
from playwright.async_api import async_playwright
from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError

from lowerduckpond_m3_qualification.report import CheckResult, EvidenceValue

REQUIRED_S3_OPERATIONS: Final = frozenset(
    {"DeleteObject", "GetObject", "ListObjectVersions", "PutObject"}
)
MINIMUM_SAFE_JSON_INTEGER: Final = -(2**53) + 1
MAXIMUM_SAFE_JSON_INTEGER: Final = 2**53 - 1


def run_library_checks() -> tuple[CheckResult, ...]:
    """Exercise the exact library capabilities M3 will depend on."""
    return (
        _run("m3.0.python.runtime", _check_python),
        _run("m3.0.python.jsonschema", _check_jsonschema),
        _run("m3.0.python.rfc8785", _check_rfc8785),
        _run("m3.0.python.hypothesis", _check_hypothesis),
        _run("m3.0.python.botocore", _check_botocore),
        _run("m3.0.python.safe-yaml", _check_safe_yaml),
        _run("m3.0.python.playwright", _check_playwright),
    )


def _run(check_id: str, operation: Callable[[], Mapping[str, EvidenceValue]]) -> CheckResult:
    try:
        evidence = operation()
    except Exception:  # The report intentionally excludes exception text.
        return CheckResult(
            check_id=check_id,
            status="failed",
            evidence={},
            error_code="probe_failed",
        )
    return CheckResult(check_id=check_id, status="passed", evidence=evidence)


def _check_python() -> dict[str, str]:
    if sys.version_info[:2] != (3, 14):
        raise RuntimeError
    return {
        "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    }


def _check_jsonschema() -> dict[str, str]:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"schema_version": {"const": "qualified"}},
        "required": ["schema_version"],
        "additionalProperties": False,
    }
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({"schema_version": "qualified"})
    try:
        validator.validate({"schema_version": "qualified", "ignored": True})
    except ValidationError:
        pass
    else:
        raise RuntimeError
    return {"draft": "2020-12", "version": version("jsonschema")}


def _check_rfc8785() -> dict[str, str]:
    canonical = rfc8785.dumps({"z": 1, "a": "é", "nested": {"b": False, "a": None}})
    expected = b'{"a":"\xc3\xa9","nested":{"a":null,"b":false},"z":1}'
    if canonical != expected:
        raise RuntimeError
    if rfc8785.dumps({"z": 1, "a": "é"}) != rfc8785.dumps({"a": "é", "z": 1}):
        raise RuntimeError
    return {"version": version("rfc8785")}


def _check_hypothesis() -> dict[str, int | str]:
    @settings(max_examples=100, derandomize=True, database=None)
    @given(
        strategies.dictionaries(
            strategies.text(max_size=20),
            strategies.integers(
                min_value=MINIMUM_SAFE_JSON_INTEGER,
                max_value=MAXIMUM_SAFE_JSON_INTEGER,
            ),
            max_size=12,
        )
    )
    def canonicalization_is_insertion_order_independent(value: dict[str, int]) -> None:
        reversed_value = dict(reversed(tuple(value.items())))
        if rfc8785.dumps(value) != rfc8785.dumps(reversed_value):
            raise RuntimeError

    canonicalization_is_insertion_order_independent()
    return {"examples": 100, "version": version("hypothesis")}


def _check_botocore() -> dict[str, int | str]:
    service_model = botocore.session.get_session().get_service_model("s3")
    available = frozenset(service_model.operation_names)
    if not REQUIRED_S3_OPERATIONS.issubset(available):
        raise RuntimeError
    return {"operations": len(REQUIRED_S3_OPERATIONS), "version": version("botocore")}


def _check_safe_yaml() -> dict[str, str]:
    yaml = YAML(typ="safe", pure=True)
    yaml.allow_duplicate_keys = False
    loaded = yaml.load("name: qualification\nenabled: true\n")
    if loaded != {"name": "qualification", "enabled": True}:
        raise RuntimeError
    try:
        yaml.load("name: first\nname: second\n")
    except DuplicateKeyError:
        pass
    else:
        raise RuntimeError
    return {"mode": "safe-pure", "version": version("ruamel.yaml")}


def _check_playwright() -> dict[str, int | str]:
    async def engine_names() -> set[str]:
        async with async_playwright() as playwright:
            return {playwright.chromium.name, playwright.firefox.name, playwright.webkit.name}

    names = asyncio.run(engine_names())
    if names != {"chromium", "firefox", "webkit"}:
        raise RuntimeError
    return {"engines": len(names), "version": version("playwright")}
