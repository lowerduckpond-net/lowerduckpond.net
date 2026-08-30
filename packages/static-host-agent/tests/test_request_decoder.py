from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import RequestDecodeError, SubprocessRequestDecoder

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"


def _helper(tmp_path: Path, body: str) -> Path:
    executable = tmp_path / "decoder"
    executable.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def test_subprocess_decoder_returns_only_canonical_request(tmp_path: Path) -> None:
    helper = _helper(
        tmp_path,
        "from lowerduckpond_static_host_agent import decoder_main; "
        "raise SystemExit(decoder_main())",
    )
    request = json.loads((_FIXTURE_ROOT / "operation-request.json").read_text(encoding="utf-8"))
    raw = json.dumps(request, indent=2).encode()

    canonical, decoded = SubprocessRequestDecoder(helper).decode(raw)

    assert canonical == canonical_json_bytes(request)
    assert decoded == request


@pytest.mark.parametrize(
    "raw",
    [
        b'{"apiVersion":"hosting.lowerduckpond.net/v1alpha1","kind":"OperationRequest",'
        b'"operation":"create","correlationId":"0198d17f-6f4a-7000-8000-000000000001",'
        b'"slug":"duck-repair","slug":"other","quotas":{"storageMiB":100,"entries":5000}}',
        (_FIXTURE_ROOT / "site.json").read_bytes(),
    ],
)
def test_subprocess_decoder_rejects_duplicate_keys_and_standalone_manifest(
    raw: bytes,
    tmp_path: Path,
) -> None:
    helper = _helper(
        tmp_path,
        "from lowerduckpond_static_host_agent import decoder_main; "
        "raise SystemExit(decoder_main())",
    )

    with pytest.raises(RequestDecodeError, match="request_invalid"):
        SubprocessRequestDecoder(helper).decode(raw)


def test_subprocess_decoder_rejects_unbounded_or_noncanonical_helper_output(
    tmp_path: Path,
) -> None:
    helper = _helper(tmp_path, 'import os; os.write(1, b"x" * 20000)')

    with pytest.raises(RequestDecodeError, match="request_decoder_failed"):
        SubprocessRequestDecoder(helper).decode(b"{}")


def test_subprocess_decoder_receives_no_ambient_environment(tmp_path: Path) -> None:
    helper = _helper(
        tmp_path,
        "import os; from lowerduckpond_static_host_agent import decoder_main; "
        "raise SystemExit(77 if 'M3_DECODER_SENTINEL' in os.environ else decoder_main())",
    )
    raw = (_FIXTURE_ROOT / "operation-request.json").read_bytes()
    os.environ["M3_DECODER_SENTINEL"] = "ambient-value"
    try:
        canonical, _ = SubprocessRequestDecoder(helper).decode(raw)
    finally:
        del os.environ["M3_DECODER_SENTINEL"]

    assert canonical == canonical_json_bytes(json.loads(raw))
