from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    HEADER_SIZE,
    FrameHeader,
    FrameKind,
    canonical_json_bytes,
    decode_header,
    decode_request,
    encode_header,
)
from lowerduckpond_static_operator import OperatorClientError, submit
from lowerduckpond_static_operator.client import print_result

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_PRIVATE_MODE = 0o600


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _regular(path: Path, content: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(content)
    path.chmod(mode)
    return path


def _fake_ssh(tmp_path: Path, response: bytes) -> tuple[Path, Path]:
    capture = tmp_path / "captured-frame"
    executable = tmp_path / "ssh"
    encoded = base64.b64encode(response).decode("ascii")
    executable.write_text(
        f"#!{sys.executable}\n"
        "import base64, pathlib, sys\n"
        f"pathlib.Path({str(capture)!r}).write_bytes(sys.stdin.buffer.read())\n"
        f"sys.stdout.buffer.write(base64.b64decode({encoded!r}))\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable, capture


def _response(
    export: bytes | None = None,
    *,
    operation: str = "create",
    correlation_id: str = "0198d17f-6f4a-7000-8000-000000000001",
) -> tuple[bytes, dict[str, object]]:
    result = _fixture("operation-result.json")
    result["correlationId"] = correlation_id
    if operation != "create":
        result["operation"] = operation
        result["manifest"] = _fixture("site.json")
    if export is not None:
        result["operation"] = "export"
        result["manifest"] = _fixture("site.json")
        result["exportBundle"] = {
            "digest": {
                "format": "lowerduckpond-archive-v1",
                "algorithm": "sha256",
                "value": hashlib.sha256(export).hexdigest(),
            },
            "size": len(export),
        }
    canonical = canonical_json_bytes(result)
    return (
        encode_header(
            FrameHeader(
                FrameKind.RESPONSE,
                len(canonical),
                len(export) if export is not None else None,
            )
        )
        + canonical
        + (export or b""),
        result,
    )


def test_client_canonicalizes_request_and_accepts_terminal_result(tmp_path: Path) -> None:
    response, expected = _response()
    ssh, capture = _fake_ssh(tmp_path, response)
    identity = _regular(tmp_path / "identity", b"private")
    request = _fixture("operation-request.json")
    request_path = _regular(tmp_path / "request.json", json.dumps(request, indent=2).encode())

    result = submit(
        host="hosting.lowerduckpond.net",
        identity_path=identity,
        request_path=request_path,
        ssh_executable=ssh,
    )

    assert result == expected
    sent = capture.read_bytes()
    header = decode_header(sent[:HEADER_SIZE], expected_kind=FrameKind.REQUEST)
    assert header.payload_length is None
    canonical = sent[HEADER_SIZE:]
    assert len(canonical) == header.document_length
    assert decode_request(canonical) == request
    assert canonical == canonical_json_bytes(request)


def test_print_result_emits_exactly_one_canonical_lf(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    result = _fixture("operation-result.json")

    print_result(result)

    assert capsysbinary.readouterr().out == canonical_json_bytes(result)


def test_client_streams_only_the_exact_bound_artifact(tmp_path: Path) -> None:
    correlation = "0198d17f-6f4a-7000-8000-000000000003"
    response, _ = _response(operation="deploy", correlation_id=correlation)
    ssh, capture = _fake_ssh(tmp_path, response)
    identity = _regular(tmp_path / "identity", b"private")
    artifact = b"artifact bytes"
    artifact_path = _regular(tmp_path / "artifact.zip", artifact)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation,
        "tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100",
        "artifact": {"size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()},
    }
    canonical = canonical_json_bytes(request)
    request_path = _regular(tmp_path / "request.json", canonical)

    submit(
        host="hosting.lowerduckpond.net",
        identity_path=identity,
        request_path=request_path,
        artifact_path=artifact_path,
        ssh_executable=ssh,
    )

    sent = capture.read_bytes()
    header = decode_header(sent[:HEADER_SIZE], expected_kind=FrameKind.REQUEST)
    assert header.document_length == len(canonical)
    assert header.payload_length == len(artifact)
    assert sent[HEADER_SIZE : HEADER_SIZE + len(canonical)] == canonical
    assert sent[HEADER_SIZE + len(canonical) :] == artifact


def test_client_writes_export_exclusively(tmp_path: Path) -> None:
    export = b"portable export"
    response, _ = _response(export)
    ssh, _ = _fake_ssh(tmp_path, response)
    identity = _regular(tmp_path / "identity", b"private")
    request = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "export",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100",
    }
    request_path = _regular(tmp_path / "request.json", canonical_json_bytes(request))
    export_path = tmp_path / "export.zip"

    submit(
        host="hosting.lowerduckpond.net",
        identity_path=identity,
        request_path=request_path,
        export_path=export_path,
        ssh_executable=ssh,
    )

    assert export_path.read_bytes() == export
    assert export_path.stat().st_mode & 0o777 == _PRIVATE_MODE


@pytest.mark.parametrize("host", ["-oProxyCommand=id", "bad..host", "host/name", ""])
def test_client_rejects_ssh_option_or_invalid_host(host: str, tmp_path: Path) -> None:
    with pytest.raises(OperatorClientError, match="host"):
        submit(
            host=host,
            identity_path=tmp_path / "missing",
            request_path=tmp_path / "missing",
        )


def test_client_rejects_exposed_identity_and_artifact_mismatch(tmp_path: Path) -> None:
    identity = _regular(tmp_path / "identity", b"private", mode=0o644)
    request_path = _regular(
        tmp_path / "request.json",
        canonical_json_bytes(_fixture("operation-request.json")),
    )
    with pytest.raises(OperatorClientError, match="identity"):
        submit(
            host="hosting.lowerduckpond.net",
            identity_path=identity,
            request_path=request_path,
        )

    identity.chmod(0o600)
    artifact = _regular(tmp_path / "unexpected.zip", b"x")
    with pytest.raises(OperatorClientError, match="does not accept"):
        submit(
            host="hosting.lowerduckpond.net",
            identity_path=identity,
            request_path=request_path,
            artifact_path=artifact,
        )


def test_client_rejects_unframed_remote_failure_without_result(tmp_path: Path) -> None:
    ssh, _ = _fake_ssh(tmp_path, b"")
    identity = _regular(tmp_path / "identity", b"private")
    request_path = _regular(
        tmp_path / "request.json",
        canonical_json_bytes(_fixture("operation-request.json")),
    )

    with pytest.raises(OperatorClientError, match="operator transport failed"):
        submit(
            host="hosting.lowerduckpond.net",
            identity_path=identity,
            request_path=request_path,
            ssh_executable=ssh,
        )
