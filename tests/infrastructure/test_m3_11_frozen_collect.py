"""Real closed collector/file linkage with only command transport synthesized."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import m3_11_frozen_budget as budget
from scripts import m3_11_frozen_collect as collect
from scripts import m3_11_frozen_github as github
from scripts import m3_11_frozen_terminal as terminal
from scripts import m3_11_frozen_terminal_bundle as bundle_module
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_retirement_files import digest, fingerprint, preserve
from scripts.m3_11_unattended.state import LeaseState, replace_private

from .test_m3_11_frozen_github import api_responses, fixture
from .test_m3_11_frozen_terminal import closed
from .test_m3_11_frozen_transport import program_for


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    tmp_path.chmod(0o700)
    manifest, contract, native = fixture()
    selected, rows, issuer, created = closed(manifest)
    lease_root = tmp_path / "lease"
    lease_root.mkdir(mode=0o700)
    lease = LeaseState(lease_root)
    write_private(lease_root / "manifest.json", selected.document())
    write_private(
        lease_root / "issuer.json",
        {"manifest_sha256": selected.sha256, "writer_sha256": issuer["writer_sha256"]},
    )
    write_private(lease_root / "issuer-stopped.json", issuer)
    for role, value in created.items():
        write_private(lease_root / ("created-" + role + ".json"), cast(dict[str, object], value))
    plan: dict[str, object] = {
        "format": "lowerduckpond-m3-11-terminal-snapshot-plan-v1",
        "implementation_revision": "a" * 40,
        "runtime_revision": "b" * 40,
        "helper_revision": selected.helper_revision,
        "lease_id": selected.lease_id,
        "manifest_sha256": selected.sha256,
        "consumer_attempt": selected.lease_id,
        "request_sha256": "c" * 64,
        "consumer_binding": "d" * 64,
        "controller_identity": {
            "id": "a" * 64,
            "image": "sha256:" + "b" * 64,
            "name": "/synthetic",
            "daemon_sha256": "e" * 64,
        },
    }
    program, bundle = program_for(
        {
            "plan": plan,
            "fixture": {},
            "runtime_revision": "b" * 40,
            "operation": "terminal-snapshot",
        }
    )
    responses = api_responses(native)
    snapshot = {
        "format": terminal.FORMAT,
        "started_at": "2026-10-18T00:00:00Z",
        "observed_at": "2026-10-18T00:00:00Z",
        "generation": {"synthetic": True},
        "reader_policy_sha256": "a" * 64,
        "journal_vault_sha256": "b" * 64,
        "authentication": "native-and-signed-policy-and-forbidden-vaults-verified",
        "inventory": rows,
        "original": terminal.retained(lease, rows),
    }
    calls: list[list[str]] = []
    command_result = {
        "status": "observed-terminal-facts",
        "snapshot": snapshot,
        "plan_sha256": digest(plan),
        "bundle_sha256": hashlib.sha256(bundle.encode()).hexdigest(),
        "provenance": {
            key: plan[key] for key in ("controller_identity", "request_sha256", "consumer_binding")
        },
    }

    def command(args: list[str], **kwargs: Any) -> bytes:  # noqa: ANN401 - command boundary
        calls.append(args)
        assert kwargs["environment"] == {"DOCKER_HOST": "unix:///synthetic"}
        if args[0] == "docker":
            assert args[:6] == ["docker", "exec", "-i", "-w", "/work/source", "a" * 64]
            assert args[-1] == program and json.loads(kwargs["stdin"])["bundle"] == bundle
            return json.dumps(command_result).encode()
        assert args[:6] == ["gh", "api", "--hostname", "github.com", "--method", "GET"]
        return responses[args[-1]]

    monkeypatch.setattr(collect, "read_command", command)
    collector = collect.Collector(
        environment={"DOCKER_HOST": "unix:///synthetic"},
        controller="a" * 64,
        program=program,
        bundle=bundle,
        plan=plan,
    )
    return SimpleNamespace(
        collector=collector,
        lease=lease,
        contract=contract,
        calls=calls,
        output=tmp_path / "capture",
        result=command_result,
        responses=responses,
    )


def capture(case: SimpleNamespace) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        case.collector.capture(
            output=case.output, run_id=456, contract=case.contract, lease=case.lease
        ),
    )


def test_full_collector_binds_all_original_responses_and_can_transfer_offline(
    case: SimpleNamespace,
) -> None:
    selection = capture(case)
    verified = bundle_module.verify(selection, case.lease)
    assert verified["credential_cleanup"] == "verified-seven-exact-denials"
    assert len(case.calls) == 8  # noqa: PLR2004 - two native snapshots plus six GETs
    registry = case.output.parent / "registry"
    registry.mkdir(mode=0o700)
    installed = {**selection, "directory": str(registry / "terminal-synthetic")}
    bundle_module.install(installed, bundle_module.pack(selection), registry=registry)
    assert bundle_module.verify(installed, case.lease)["native"] == verified["native"]
    assert len(case.calls) == 8  # noqa: PLR2004 - no network/provider calls during offline install


def test_large_native_response_survives_capture_and_complete_offline_transfer(
    case: SimpleNamespace,
) -> None:
    # Actual native JSON is allowed up to 4 MiB, independently of the 1 MiB
    # streaming chunk size. Exercise both writers and the full file consumer.
    endpoint = "repos/lowerduckpond-net/lowerduckpond.net/actions/runs/456"
    native = json.loads(case.responses[endpoint])
    native["large_native_metadata"] = "x" * (1024 * 1024)
    case.responses[endpoint] = json.dumps(native).encode()
    assert 1024 * 1024 < len(case.responses[endpoint]) < github.MAX_BODY
    test_full_collector_binds_all_original_responses_and_can_transfer_offline(case)


@pytest.mark.parametrize(
    "change", ["endpoint", "raw", "native-provenance", "missing-call", "elapsed", "attempts"]
)
def test_rebinding_labels_does_not_replace_full_native_linkage(
    case: SimpleNamespace, change: str
) -> None:
    selected = capture(case)
    rows = read_private(case.output / "native-calls.json")
    calls = cast(list[dict[str, object]], rows["calls"])
    if change == "endpoint":
        calls[1]["endpoint"] = str(calls[1]["endpoint"]).replace("456", "999")
    elif change == "missing-call":
        calls.pop()
    elif change == "elapsed":
        calls[1]["elapsed_seconds"] = 901
    elif change == "attempts":
        calls[1]["attempt_count"] = 2
    else:
        index = 0 if change == "native-provenance" else 1
        path = case.output / f"response-{index}.bin"
        value = json.loads(path.read_bytes())
        if change == "native-provenance":
            value["provenance"]["request_sha256"] = "f" * 64
        else:
            value["id"] = 999
        replace_private(path, value)
        calls[index]["response_sha256"] = fingerprint(path, github.MAX_ZIP)["sha256"]
        selected["files"][path.name] = fingerprint(path, github.MAX_ZIP)
    replace_private(case.output / "native-calls.json", rows)
    for index, call in enumerate(calls):
        path = case.output / f"call-{index}.json"
        replace_private(path, call)
        selected["files"][path.name] = fingerprint(path, github.MAX_ZIP)
    selected["files"]["native-calls.json"] = fingerprint(
        case.output / "native-calls.json", github.MAX_ZIP
    )
    with pytest.raises(ValueError):
        bundle_module.verify(selected, case.lease)


@pytest.mark.parametrize("operation", ["snapshot", "github"])
def test_enclosing_clock_admits_the_whole_native_call_before_submission(
    case: SimpleNamespace, operation: str
) -> None:
    seconds = (
        budget.SNAPSHOT_CALL_SECONDS if operation == "snapshot" else budget.GITHUB_CALL_SECONDS
    )
    case.collector.deadline = time.monotonic() + seconds
    with pytest.raises(ValueError, match="whole"):
        if operation == "snapshot":
            case.collector.snapshot()
        else:
            case.collector.github_get("repos/lowerduckpond-net/lowerduckpond.net/actions/runs/456")
    assert case.calls == []


def test_failed_read_keeps_safe_chain_phase_and_attempt_without_secret_text(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed(*_args: object, **_kwargs: object) -> bytes:
        try:
            raise OSError(101, "secret-token https://private.invalid?token=secret")
        except OSError as error:
            raise TimeoutError("secret-password") from error

    monkeypatch.setattr(collect, "read_command", failed)
    with pytest.raises(TimeoutError):
        capture(case)
    report = read_private(case.output / "failure.json")
    assert report["phase"] == "terminal-snapshot" and report["attempt_count"] == 1
    assert report["completed_reads"] == 0 and report["provider_mutations"] == 0
    assert "secret" not in json.dumps(report) and "private.invalid" not in json.dumps(report)
    assert "TimeoutError" in json.dumps(report) and "101" in json.dumps(report)


def test_terminal_publication_interruption_preserves_bytes_without_stranding_destination(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    selection = capture(case)
    registry = case.output.parent / "registry"
    registry.mkdir(mode=0o700)
    selected = {**selection, "directory": str(registry / "terminal-synthetic")}
    encoded = bundle_module.pack(selection)
    original = preserve

    def interrupted(*args: Any, **kwargs: Any) -> dict[str, object]:  # noqa: ANN401 - fsync boundary
        result = original(*args, **kwargs)
        raise KeyboardInterrupt(result["size"])

    monkeypatch.setattr(bundle_module, "preserve", interrupted)
    with pytest.raises(KeyboardInterrupt):
        bundle_module.install(selected, encoded, registry=registry)
    partial = next(registry.glob("*.unpublished-*"))
    retained = {path: path.read_bytes() for path in partial.rglob("*") if path.is_file()}
    assert retained and not Path(selected["directory"]).exists()
    monkeypatch.setattr(bundle_module, "preserve", original)
    bundle_module.install(selected, encoded, registry=registry)
    assert retained == {path: path.read_bytes() for path in partial.rglob("*") if path.is_file()}
    bundle_module.verify(selected, case.lease)
