"""Fail closed on foreign DNS, changed original names, and incomplete observations."""

from __future__ import annotations

import hashlib
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import m3_11_dns_witness as dns
from scripts import m3_11_qualification_evidence as evidence
from scripts.check_m3_7_production_edge import CloudflareClient
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import PRIVATE_FILE_MODE, read_private, write_private
from scripts.production_qualification_inputs import POLICY


@dataclass
class Run:
    directory: Path
    storage: LiveStorage
    client: Mock
    policy: Mock
    names: tuple[str, str]

    def begin(self) -> dns.DnsWitness:
        return dns.DnsWitness.begin(self.directory, self.storage)


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Run:
    target = Target(str(uuid.uuid7()), "ams3", "fixture-backups", "fixture-archives")
    binding: dict[str, object] = {
        "source_revision": "a" * 40,
        "artifact_sha256": "b" * 64,
        "input_policy": POLICY,
        "qualification_inputs_sha256": "c" * 64,
        "storage_target_sha256": target.storage_target_sha256,
        "storage_run_id": str(uuid.uuid7()),
        "storage_report_sha256": "d" * 64,
    }
    environment = {
        "CLOUDFLARE_API_TOKEN": "fixture-independent-reader",
        "CADDY_CLOUDFLARE_API_TOKEN": "fixture-caddy-runtime-token",
        "M3_10_TOKEN_AUDIT_TOKEN": "fixture-independent-auditor",
        "CLOUDFLARE_ZONE_ID": "1" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "2" * 32,
        "M3_10_INSTALLED_REPORT": str(tmp_path / "installed.json"),
    }
    storage = LiveStorage(
        target, binding, "original-owner-version", environment, "fixture-password"
    )
    monkeypatch.setattr(LiveStorage, "require_source", Mock())
    nonce = str(uuid.uuid7())
    write_private(
        tmp_path / "combined-context.json",
        {
            "format": evidence.CONTEXT_FORMAT,
            "run_id": target.run_id,
            "captured_at": "2026-09-24T22:00:00Z",
            **binding,
            **dict.fromkeys(evidence.IDENTITY_FIELDS, "e" * 64),
            "subject_set_sha256": evidence.subject_digest(nonce),
        },
    )
    write_private(
        tmp_path / "combined-names.json",
        {
            "format": evidence.NAMES_FORMAT,
            "run_id": target.run_id,
            "nonce": nonce,
            "subjects": list(evidence.subjects(nonce)),
        },
    )
    client = Mock(spec=CloudflareClient)
    client.get.side_effect = [
        {"id": zone_id, "name": domain, "status": "active", "account": {"id": "3" * 32}}
        for zone_id, domain in (("1" * 32, "lowerduckpond.net"), ("2" * 32, "lowerduckpond.com"))
    ]
    client.get_collection.return_value = []
    monkeypatch.setattr(dns, "CloudflareClient", Mock(return_value=client))
    policy = Mock()
    monkeypatch.setattr(dns, "check_caddy_token", policy)
    names = tuple(
        f"_acme-challenge.m3-11-{uuid.UUID(nonce).hex}.{domain}" for domain, _ in dns.ZONES
    )
    return Run(tmp_path, storage, client, policy, (names[0], names[1]))


def record(name: str, number: int = 1, **changes: object) -> dict[str, object]:
    return {"id": f"{number:032x}", "name": name, "type": "TXT", "content": "A" * 43, **changes}


def authorize_removal(run: Run) -> dns.Observation:
    witness = run.begin()
    observation = witness.require_absent("teardown")
    (run.directory / "owned-teardown").mkdir(mode=0o700)
    write_private(
        run.directory / "owned-teardown/intent.json",
        {
            "context_sha256": witness.context_sha256,
            "dns_sha256": observation.sha256,
        },
    )
    run.client.get.side_effect = [
        {"id": zone_id, "name": domain, "status": "active", "account": {"id": "3" * 32}}
        for zone_id, domain in (("1" * 32, "lowerduckpond.net"), ("2" * 32, "lowerduckpond.com"))
    ]
    return observation


def test_cleanup_after_a_failed_attempt_appends_without_replacing_original_dns(run: Run) -> None:
    original = authorize_removal(run)
    before = {path: path.read_bytes() for path in original.path.parent.iterdir()}
    observation = dns.removal_absence(run.directory, run.storage)
    assert observation.record_count == 0
    assert observation.path.name == "0002.json"
    assert read_private(observation.path)["kind"] == "teardown"
    assert all(path.read_bytes() == raw for path, raw in before.items())
    run.policy.assert_called_once()  # Cleanup never starts or authorizes another issuer.
    assert not (run.directory / "combined.json").exists()


@pytest.mark.parametrize(
    "fault",
    ["zone", "context", "gap", "baseline", "authorization", "changed-hash", "count", "provider"],
)
def test_cleanup_cannot_adopt_changed_names_or_discard_previous_observations(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    original = authorize_removal(run)
    if fault == "zone":
        assert isinstance(run.storage.environment, dict)
        run.storage.environment["CLOUDFLARE_ZONE_ID"] = "4" * 32
    elif fault == "gap":
        original.path.rename(original.path.with_name("0003.json"))
    elif fault == "count":
        monkeypatch.setattr(dns, "MAX_OBSERVATIONS", 2)
    elif fault == "provider":
        run.client.get_collection.side_effect = [[record(run.names[0])], []]
    else:
        path = run.directory / (
            "combined-context.json"
            if fault == "context"
            else "public-dns/0000.json"
            if fault == "baseline"
            else "owned-teardown/intent.json"
            if fault == "authorization"
            else "public-dns/0001.json"
        )
        value = read_private(path)
        if fault == "context":
            value["storage_run_id"] = str(uuid.uuid7())
        elif fault == "baseline":
            value["kind"] = "cleanup"
        elif fault == "authorization":
            value["dns_sha256"] = "0" * 64
        else:
            value["completed_at"] = "changed original observation"
        path.write_bytes(evidence.canonical_bytes(value))
    with pytest.raises(ValueError):
        dns.removal_absence(run.directory, run.storage)
    assert not (run.directory / "combined.json").exists()


def test_independent_dns_keeps_original_baseline_activity_and_cleanup(run: Run) -> None:
    witness = run.begin()
    run.policy.assert_called_once()
    assert run.policy.call_args.kwargs["account_id"] == "3" * 32
    baseline = (run.directory / "public-dns/0000.json").read_bytes()
    run.client.get_collection.assert_any_call(
        "/zones/" + "1" * 32 + "/dns_records", query={"name": run.names[0]}
    )
    # Apex and wildcard may use separate records at the same challenge name.
    run.client.get_collection.side_effect = [[record(run.names[0]), record(run.names[0], 2)], []]
    first = witness.sample()
    assert first.record_count == len(run.names)
    with pytest.raises(ValueError, match="both zones"):
        witness.require_both_zones_observed()
    run.client.get_collection.side_effect = [[], [record(run.names[1], 3)]]
    second = witness.sample()
    witness.require_both_zones_observed()
    run.client.get_collection.side_effect = None
    final = witness.require_absent("cleanup")
    assert not final.active_zones and final.record_count == 0
    assert first.sha256 == hashlib.sha256(first.path.read_bytes()).hexdigest()
    assert second.sha256 != first.sha256 != final.sha256
    assert (run.directory / "public-dns/0000.json").read_bytes() == baseline
    assert all(
        stat.S_IMODE(path.stat().st_mode) == PRIVATE_FILE_MODE
        for path in final.path.parent.iterdir()
    )
    assert read_private(final.path)["kind"] == "cleanup"
    assert all(
        b"fixture-independent-reader" not in path.read_bytes()
        for path in final.path.parent.iterdir()
    )


@pytest.mark.parametrize("kind", ["TXT", "CNAME", "A"])
def test_any_preexisting_record_fails_and_original_observation_is_retained(
    run: Run, kind: str
) -> None:
    run.client.get_collection.side_effect = [[record(run.names[0], type=kind)], []]
    with pytest.raises(ValueError, match="not empty"):
        run.begin()
    original = (run.directory / "public-dns/0000.json").read_bytes()
    assert kind.encode() in original
    # Even an emptied name cannot replace this failed attempt's baseline.
    run.client.get.side_effect = None
    run.client.get_collection.side_effect = None
    with pytest.raises(ValueError, match="already allocated"):
        run.begin()
    assert (run.directory / "public-dns/0000.json").read_bytes() == original


@pytest.mark.parametrize("fault", ["names", "storage-run", "same-zone", "bad-zone", "token-policy"])
def test_changed_identity_or_token_policy_fails_before_dns_observation(
    run: Run, fault: str
) -> None:
    if fault == "names":
        path = run.directory / "combined-names.json"
        names = read_private(path)
        names["subjects"] = ["lowerduckpond.net"]
        path.write_bytes(evidence.canonical_bytes(names))
    elif fault == "storage-run":
        path = run.directory / "combined-context.json"
        context = read_private(path)
        context["storage_run_id"] = str(uuid.uuid7())
        path.write_bytes(evidence.canonical_bytes(context))
    elif fault in {"same-zone", "bad-zone"}:
        assert isinstance(run.storage.environment, dict)
        run.storage.environment["CLOUDFLARE_TENANT_ZONE_ID"] = (
            "1" * 32 if fault == "same-zone" else "../foreign"
        )
    else:
        run.policy.side_effect = ValueError("runtime token policy changed")
    with pytest.raises(ValueError):
        run.begin()
    run.client.get_collection.assert_not_called()
    assert not (run.directory / "public-dns").exists()


@pytest.mark.parametrize("fault", ["account", "zone-name", "inactive"])
def test_observer_must_identify_the_original_two_active_zones(run: Run, fault: str) -> None:
    zones = [
        {"id": zone_id, "name": domain, "status": "active", "account": {"id": "3" * 32}}
        for zone_id, domain in (("1" * 32, "lowerduckpond.net"), ("2" * 32, "lowerduckpond.com"))
    ]
    if fault == "account":
        zones[1]["account"] = {"id": "4" * 32}
    elif fault == "zone-name":
        zones[1]["name"] = "foreign.test"
    else:
        zones[1]["status"] = "pending"
    run.client.get.side_effect = zones
    with pytest.raises((ValueError, RuntimeError)):
        run.begin()
    run.client.get_collection.assert_not_called()
    run.policy.assert_not_called()


@pytest.mark.parametrize(
    "fault", ["foreign-name", "bad-id", "duplicate", "too-many", "content", "cname", "api-failure"]
)
def test_incomplete_or_unrelated_activity_cannot_qualify(run: Run, fault: str) -> None:
    witness = run.begin()
    values: list[object] = [record(run.names[0])]
    if fault == "foreign-name":
        values = [record("production.lowerduckpond.net")]
    elif fault == "bad-id":
        values = [record(run.names[0], id="../foreign")]
    elif fault == "duplicate":
        values *= 2
    elif fault == "too-many":
        values = [record(run.names[0], number) for number in range(dns.MAX_RECORDS_PER_NAME + 1)]
    elif fault == "content":
        values = [record(run.names[0], content="not an ACME challenge")]
    elif fault == "cname":
        values = [record(run.names[0], type="CNAME")]
    if fault == "api-failure":
        run.client.get_collection.side_effect = [values, ValueError("incomplete pagination")]
    else:
        run.client.get_collection.side_effect = [values, []]
    with pytest.raises(ValueError):
        witness.sample()
    assert not witness.observed_zones
    with pytest.raises(ValueError, match="both zones"):
        witness.require_both_zones_observed()
    run.client.get_collection.side_effect = None
    run.client.get_collection.reset_mock()
    with pytest.raises(ValueError, match="previously failed"):
        witness.sample()
    run.client.get_collection.assert_not_called()


def test_cleanup_and_teardown_each_require_fresh_independent_absence(run: Run) -> None:
    witness = run.begin()
    witness.require_absent("cleanup")
    run.client.get_collection.side_effect = [[], [record(run.names[1])]]
    with pytest.raises(ValueError, match="not empty"):
        witness.require_absent("teardown")
    assert read_private(run.directory / "public-dns/0002.json")["kind"] == "teardown"


@pytest.mark.parametrize("fault", ["names", "context", "bound", "original-file"])
def test_observation_cannot_change_names_exceed_bounds_or_replace_originals(
    run: Run, fault: str
) -> None:
    witness = run.begin()
    run.client.get_collection.reset_mock()
    if fault in {"names", "context"}:
        path = run.directory / f"combined-{fault}.json"
        value = read_private(path)
        value["run_id"] = str(uuid.uuid7())
        path.write_bytes(evidence.canonical_bytes(value))
    elif fault == "bound":
        witness.sequence = dns.MAX_OBSERVATIONS
    else:
        write_private(run.directory / "public-dns/0001.json", {"original": "partial attempt"})
    with pytest.raises((ValueError, FileExistsError)):
        witness.sample()
    if fault != "original-file":
        run.client.get_collection.assert_not_called()
    else:
        assert read_private(run.directory / "public-dns/0001.json") == {
            "original": "partial attempt"
        }


@pytest.mark.parametrize("interrupt_at", [0, 600, 1790])
@pytest.mark.parametrize("expires", [False, True])
def test_public_polling_can_use_the_full_deadline_and_retain_cleanup_evidence(
    run: Run,
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
    interrupt_at: int,
    expires: bool,
) -> None:
    module = installed_module("public_ca_recovery")
    previous_observation_limit = 240
    elapsed = 0
    ready = False

    def sleep(seconds: int) -> None:
        nonlocal elapsed
        elapsed += seconds

    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: elapsed, sleep=sleep))
    monkeypatch.setattr(module.PublicRecovery, "_identity", Mock())
    monkeypatch.setattr(module.PublicRecovery, "peer", Mock())
    monkeypatch.setattr(module, "gate_closed", Mock())
    monkeypatch.setattr(module, "require_original", Mock(return_value={}))
    monkeypatch.setattr(module, "_selected_python", lambda host, body: body)
    (run.directory / "public-inputs").mkdir(mode=0o700)
    write_private(run.directory / "public-inputs/original.json", {})
    fixture = Mock(
        live_storage=run.storage, binary="fixture", target={"auditRotationEnabled": False}
    )
    recovery = module.PublicRecovery(fixture, run.storage, run.directory)
    original_deadline = recovery.deadline

    def records(path: str, *, query: dict[str, str]) -> list[dict[str, object]]:
        return [record(query["name"])] if elapsed >= interrupt_at and not ready else []

    def call(action: str, **arguments: object) -> dict[str, object]:
        nonlocal ready
        if action != "stop_failed":
            recovery._remaining()
        if action == "ready":
            ready = not expires and elapsed >= module.COORDINATOR_SECONDS - 5
            return {"ready": ready, "tls": {"issuer": "fixture", "certificates": []}}
        return {"action": action}

    run.client.get_collection.side_effect = records
    recovery.call = Mock(side_effect=call)
    if expires:
        with pytest.raises(TimeoutError, match="original coordinator deadline"):
            recovery.run()
        assert recovery.call.call_args_list[-1].args == ("stop_failed",)
        assert "open_verified" not in [item.args[0] for item in recovery.call.call_args_list]
        assert not (run.directory / "public-ca.json").exists()
        assert elapsed == module.COORDINATOR_SECONDS
    else:
        _, details = recovery.run()
        # Normal teardown independently checks absence before and after removal.
        before = recovery.witness.require_absent("teardown")
        after = recovery.witness.require_absent("teardown")
        assert before.sha256 != after.sha256
        assert recovery.witness.sequence <= dns.MAX_OBSERVATIONS
        assert (run.directory / "public-ca.json").exists()
        assert len(details["dns_activity_sha256"]) > previous_observation_limit
        assert elapsed == module.COORDINATOR_SECONDS - 5
    assert recovery.deadline == original_deadline
    fixture.reboot.assert_called_once()
