"""No-network regressions for the distinct three-role diagnostic boundary."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe
from scripts.m3_11_isolation_contract import PERMISSIONS, Intent, Network, Plan, require_three
from scripts.m3_11_isolation_dns import Readers
from scripts.m3_11_isolation_lease import Lease, Provider
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.model import Credential, LeaseManifest

NOW = datetime(2026, 10, 29, tzinfo=UTC)
START = "2026-10-29T00:00:00Z"
BEFORE = "2026-10-29T00:10:00Z"
EXPIRES = "2026-10-29T04:00:00Z"
SECRET = "fake-only-private-canary-not-a-credential"  # noqa: S105 - synthetic canary


@pytest.fixture
def plan() -> Plan:
    return Plan(
        str(uuid.uuid7()),
        str(uuid.uuid7()),
        "a" * 40,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "0" * 64,
        "a" * 32,
        {"lowerduckpond.net": "b" * 32, "lowerduckpond.com": "c" * 32},
        Network("authoritative", ()),
        "unix:///synthetic/docker.sock",
        "f" * 64,
        "2026-10-28T23:59:00Z",
        BEFORE,
        14400,
        1800,
        604800,
        "synthetic-test-approval",
        "9" * 64,
    )


@pytest.fixture
def intents(plan: Plan) -> tuple[Intent, ...]:
    return tuple(
        Intent(
            plan,
            role,
            START,
            BEFORE,
            EXPIRES,
            {hashlib.sha256(name.encode()).hexdigest()[:32]: name for name in PERMISSIONS[role]},
            (),
            "e" * 64,
            "d" * 64,
            "synthetic-test-approval",
        )
        for role in sorted(PERMISSIONS)
    )


def metadata(intent: Intent, selected: str) -> dict[str, object]:
    return {
        "id": selected,
        "name": intent.plan.token_name(intent.role),
        "issued_on": START,
        "not_before": START,
        "expires_on": EXPIRES,
        "status": "active",
        "policies": [
            {
                "effect": "allow",
                "permission_groups": [
                    {"id": key, "name": value} for key, value in intent.permission_ids.items()
                ],
                "resources": dict.fromkeys(intent.plan.resources(intent.role), "*"),
            }
        ],
    }


class Journal:
    def __init__(self) -> None:
        self.values: list[dict[str, object]] = []
        self.reservations: set[str] = set()
        self.fail: str | None = None

    def persist(self, value: dict[str, object]) -> None:
        if value["kind"] == self.fail:
            raise OSError(SECRET)
        self.values.append(deepcopy(value))

    def records(self) -> list[dict[str, object]]:
        return deepcopy(self.values)

    def reserve(self, run_id: str, value: dict[str, object]) -> None:
        if run_id in self.reservations:
            raise FileExistsError("already reserved")
        self.reservations.add(run_id)
        self.persist(value)


class FakeProvider:
    def __init__(self, plan: Plan) -> None:
        self.account = plan.account_id
        self.authority_sha256 = "d" * 64
        self.items: dict[str, dict[str, object]] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.fail_create: str | None = None
        self.fail_delete: str | None = None
        self.deny = True
        self.verify = True

    def inventory(self) -> list[str]:
        return list(self.items)

    def require_scope(self, intent: Intent) -> None:
        assert intent.plan.account_id == self.account

    def inspect(self, selected: str) -> dict[str, object] | None:
        return self.items.get(selected)

    def create(self, intent: Intent, record: Callable[[str, str | None], None]) -> Credential:
        self.created.append(intent.role)
        if intent.role == self.fail_create:
            raise OSError(SECRET)
        selected = hashlib.sha256(intent.role.encode()).hexdigest()[:32]
        self.items[selected] = metadata(intent, selected)
        record(selected, SECRET + "-" + intent.role)
        return Credential(selected, SECRET + "-" + intent.role, self.items[selected])

    def active(self, selected: str, secret: str) -> bool:
        assert secret.startswith(SECRET)
        return selected in self.items and self.verify

    def delete(self, selected: str) -> None:
        if self.items[selected]["name"] == self.fail_delete:
            raise OSError(SECRET)
        self.deleted.append(selected)
        self.items.pop(selected)

    def denied(self, selected: str, secret: str) -> bool:
        assert secret.startswith(SECRET)
        return selected not in self.items and self.deny


def issue(
    lease: Lease, provider: FakeProvider, prearmed: Callable[[], None] = lambda: None
) -> dict[str, str]:
    original = provider.authority_sha256
    provider.authority_sha256 = "e" * 64
    try:
        return lease.issue(cast(Provider, provider), now=lambda: NOW, require_prearmed=prearmed)
    finally:
        provider.authority_sha256 = original


@pytest.mark.parametrize(
    "network",
    [
        None,
        {},
        {"mode": None, "resolvers": []},
        {"mode": "authoritative", "resolvers": ["192.0.2.1"]},
        {"mode": "recursive-precheck", "resolvers": []},
        {"mode": "off", "resolvers": []},
    ],
)
def test_no_implicit_dns_mode_or_relaxed_propagation(network: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        Network.parse(network)
    with pytest.raises(ValueError):
        policy.isolation_configuration(str(uuid.uuid7()), network)


def test_recursive_mode_changes_only_explicit_resolvers(plan: Plan) -> None:
    native = json.loads(policy.configuration(plan.nonce))
    direct = policy.isolation_configuration(plan.nonce, plan.network.document())
    assert direct == policy.configuration(plan.nonce)
    network = Network.parse({"mode": "recursive-precheck", "resolvers": ["192.0.2.1"]})
    recursive = json.loads(policy.isolation_configuration(plan.nonce, network.document()))
    dns = recursive["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"]
    assert dns.pop("resolvers") == ["192.0.2.1"]
    assert recursive == native
    assert "propagation_timeout" not in dns


@pytest.mark.parametrize("role", ["archive", "backup", "operator", "page-rules", "unknown"])
def test_contract_cannot_select_storage_or_page_rules(plan: Plan, role: str) -> None:
    with pytest.raises(ValueError):
        plan.token_name(role)


def test_plan_roundtrip_is_exact_and_unknown_fields_fail(plan: Plan) -> None:
    assert Plan.parse(plan.document()) == plan
    with pytest.raises((ValueError, TypeError)):
        Plan.parse({**plan.document(), "qualification": True})
    with pytest.raises((ValueError, TypeError)):
        Plan.parse({**plan.document(), "network": None})


@pytest.mark.parametrize(
    "field",
    [
        "source_revision",
        "controller_sha256",
        "artifact_sha256",
        "caddy_binary_sha256",
        "fixture_image_sha256",
        "account_id",
    ],
)
def test_bad_source_runtime_and_account_bindings_fail(plan: Plan, field: str) -> None:
    with pytest.raises((ValueError, TypeError, RuntimeError)):
        Plan.parse({**plan.document(), field: "invalid"})


@pytest.mark.parametrize(
    "change",
    [
        "name",
        "issued_on",
        "expires_on",
        "not_before",
        "status",
        "condition",
        "scope",
        "baseline-id",
    ],
)
def test_revocation_requires_exact_full_ownership(intents: tuple[Intent, ...], change: str) -> None:
    intent = intents[0]
    item = metadata(intent, "0" * 32)
    if change == "scope":
        item["policies"] = []
    elif change == "baseline-id":
        intent = replace(intent, baseline_ids=("0" * 32,))
    elif change == "condition":
        item["condition"] = {"request.ip": {"in": ["192.0.2.1"]}}
    else:
        item[change] = "invalid"
    with pytest.raises((ValueError, RuntimeError)):
        intent.require_owned(item)


def test_exact_three_roles_share_scope_time_and_cleanup(intents: tuple[Intent, ...]) -> None:
    assert require_three(intents, now=NOW) is intents[0].plan
    with pytest.raises(ValueError):
        require_three(intents[:2], now=NOW)
    with pytest.raises(ValueError):
        require_three(
            (replace(intents[0], cleanup_authority_sha256="e" * 64), *intents[1:]), now=NOW
        )
    with pytest.raises(ValueError):
        require_three(intents, now=datetime(2026, 10, 29, 1, tzinfo=UTC))


def test_no_provider_effect_before_independent_intent_ack(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    journal = Journal()
    journal.fail = "intents"
    lease, provider = Lease(tmp_path, intents, journal), FakeProvider(intents[0].plan)
    with pytest.raises(OSError):
        issue(lease, provider)
    assert provider.created == []
    with pytest.raises((FileExistsError, ValueError)):
        issue(lease, provider)


def test_no_provider_effect_before_prearmed_cleanup(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    lease, provider = Lease(tmp_path, intents, Journal()), FakeProvider(intents[0].plan)
    armed = Mock(side_effect=ValueError("not armed"))
    with pytest.raises(ValueError):
        issue(lease, provider, armed)
    assert not (tmp_path / "issue-entered.json").exists()
    assert provider.created == []


def test_unknown_create_is_never_replayed_or_relabelled_closed(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    lease, provider = Lease(tmp_path, intents, Journal()), FakeProvider(intents[0].plan)
    provider.fail_create = "caddy"
    with pytest.raises(OSError):
        issue(lease, provider)
    assert provider.created == ["audit", "caddy"]
    with pytest.raises((FileExistsError, ValueError)):
        issue(lease, provider)
    with pytest.raises(ValueError, match="pending"):
        lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert not (tmp_path / "closed.json").exists()
    assert provider.items == {}  # known audit still cleaned despite caddy uncertainty
    assert SECRET not in json.dumps(
        [read_private(path) for path in tmp_path.glob("cleanup-pending-*.json")]
    )


def test_cleanup_attempts_other_roles_after_a_provider_failure(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    lease, provider = Lease(tmp_path, intents, Journal()), FakeProvider(intents[0].plan)
    issue(lease, provider)
    provider.fail_delete = intents[0].plan.token_name("audit")
    with pytest.raises(ValueError, match="pending"):
        lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert len(provider.deleted) == len(PERMISSIONS) - 1
    assert len(provider.items) == 1
    assert not (tmp_path / "closed.json").exists()


def test_fence_and_authority_mismatch_stop_cleanup(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    lease, provider = Lease(tmp_path, intents, Journal()), FakeProvider(intents[0].plan)
    issue(lease, provider)
    with pytest.raises(ValueError):
        lease.cleanup(
            cast(Provider, provider),
            require_issuer_stopped=Mock(side_effect=ValueError("issuer alive")),
        )
    assert provider.deleted == []
    provider.authority_sha256 = "e" * 64
    with pytest.raises(ValueError):
        lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert provider.deleted == []


def test_absence_is_insufficient_without_denied_authentication(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    lease, provider = Lease(tmp_path, intents, Journal()), FakeProvider(intents[0].plan)
    issue(lease, provider)
    provider.deny = False
    with pytest.raises(ValueError):
        lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert len(provider.deleted) == len(PERMISSIONS)
    assert not (tmp_path / "closed.json").exists()


def test_full_closure_needs_fresh_independent_provider_and_journal_readback(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    journal = Journal()
    lease, provider = Lease(tmp_path, intents, journal), FakeProvider(intents[0].plan)
    ids = issue(lease, provider)
    assert set(ids) == PERMISSIONS.keys()
    expected = lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    receipt = lease.independent_readback(
        cast(Provider, provider), expected=expected, require_issuer_stopped=lambda: None
    )
    assert receipt["provider_absent"] is True
    assert receipt["journal_matches"] is True
    assert len(list(tmp_path.glob("*.credential"))) == len(PERMISSIONS)
    provider.items[ids["caddy"]] = metadata(intents[1], ids["caddy"])
    with pytest.raises(ValueError):
        lease.independent_readback(
            cast(Provider, provider), expected=expected, require_issuer_stopped=lambda: None
        )
    provider.items.clear()
    journal.values = [value for value in journal.values if value["kind"] != "closed"]
    with pytest.raises(ValueError):
        lease.independent_readback(
            cast(Provider, provider), expected=expected, require_issuer_stopped=lambda: None
        )


def test_provider_constructor_cannot_select_digitalocean() -> None:
    with pytest.raises(ValueError):
        Provider(Api("https://api.digitalocean.com", SECRET), account="a" * 32)


def test_isolated_install_rejects_unset_mode_before_any_guest_mutation(
    monkeypatch: pytest.MonkeyPatch, plan: Plan
) -> None:
    mutation = Mock(side_effect=AssertionError("must not mutate"))
    monkeypatch.setattr(probe, "_fixture", mutation)
    with pytest.raises(ValueError):
        probe.install_isolated({"nonce": plan.nonce, "token": SECRET})
    mutation.assert_not_called()


def test_guest_program_uses_real_helpers_and_no_token_argv(
    installed_module: Callable[[str], ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = installed_module("public_ca_recovery")
    monkeypatch.setattr(module, "_selected_python", lambda host, body: body)
    program = module.program(Mock(), isolated=True)
    assert SECRET not in program
    result = subprocess.run(  # noqa: S603 - real helpers; unset mode forbids mutation
        [sys.executable, "-c", program],
        input=b'{"action":"install_isolated","value":{}}',
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert b"isolated public DNS mode is unset or malformed" in result.stderr
    assert SECRET.encode() not in result.stdout + result.stderr


def test_isolated_result_cannot_be_native_combined_qualification(plan: Plan) -> None:
    with pytest.raises((ValueError, RuntimeError)):
        LeaseManifest.parse(plan.document())
    assert "qualification" not in Plan.__dataclass_fields__
    assert "spaces" not in Provider.__dict__


def test_private_readers_repr_omits_credential_values() -> None:
    assert SECRET not in repr(Readers(SECRET, SECRET + "1", SECRET + "2"))


def test_global_reservation_prevents_an_alternate_directory_replay(
    tmp_path: Path, intents: tuple[Intent, ...]
) -> None:
    journal, provider = Journal(), FakeProvider(intents[0].plan)
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    issue(Lease(first, intents, journal), provider)
    with pytest.raises(ValueError, match="prior obligations"):
        issue(Lease(second, intents, journal), provider)
    journal.values.clear()  # Synthetic stale listing; reservation must still prevent POST.
    with pytest.raises(FileExistsError):
        issue(Lease(second, intents, journal), provider)
    assert len(provider.created) == len(PERMISSIONS)


def test_journal_io_cannot_extend_create_admission(
    tmp_path: Path,
    intents: tuple[Intent, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [NOW]
    journal = Journal()
    original = journal.persist

    def delayed(value: dict[str, object]) -> None:
        original(value)
        if value["kind"] == "entered":
            clock[0] = datetime(2026, 10, 29, 0, 11, tzinfo=UTC)

    monkeypatch.setattr(journal, "persist", delayed)
    provider = FakeProvider(intents[0].plan)
    provider.authority_sha256 = "e" * 64
    with pytest.raises(ValueError):
        Lease(tmp_path, intents, journal).issue(
            cast(Provider, provider),
            now=lambda: clock[0],
            require_prearmed=lambda: None,
        )
    assert provider.created == []


def test_registry_mismatch_is_rejected_before_post(
    tmp_path: Path,
    intents: tuple[Intent, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = FakeProvider(intents[0].plan)
    monkeypatch.setattr(
        provider, "require_scope", Mock(side_effect=ValueError("registry mismatch"))
    )
    with pytest.raises(ValueError):
        issue(Lease(tmp_path, intents, Journal()), provider)
    assert provider.created == []


def test_changed_provider_inventory_is_rejected_before_post(
    tmp_path: Path,
    intents: tuple[Intent, ...],
) -> None:
    provider = FakeProvider(intents[0].plan)
    provider.items["0" * 32] = {"unrelated": True}
    with pytest.raises(ValueError, match="inventory changed"):
        issue(Lease(tmp_path, intents, Journal()), provider)
    assert provider.created == []


@pytest.mark.parametrize("status", ["expired", "disabled"])
def test_cleanup_accepts_exact_owned_expired_or_disabled_credentials(
    tmp_path: Path,
    intents: tuple[Intent, ...],
    status: str,
) -> None:
    lease, provider = Lease(tmp_path, intents, Journal()), FakeProvider(intents[0].plan)
    issue(lease, provider)
    for item in provider.items.values():
        item["status"] = status
    lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert len(provider.deleted) == len(PERMISSIONS)


def test_journal_outage_does_not_skip_known_revocations_or_claim_closure(
    tmp_path: Path,
    intents: tuple[Intent, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal, provider = Journal(), FakeProvider(intents[0].plan)
    lease = Lease(tmp_path, intents, journal)
    issue(lease, provider)
    monkeypatch.setattr(journal, "records", Mock(side_effect=OSError(SECRET)))
    monkeypatch.setattr(journal, "persist", Mock(side_effect=OSError(SECRET)))
    with pytest.raises(ValueError, match="cleanup remains pending"):
        lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert len(provider.deleted) == len(PERMISSIONS)
    assert not (tmp_path / "closed.json").exists()


def test_missing_entered_marker_cannot_hide_a_known_created_credential(
    tmp_path: Path,
    intents: tuple[Intent, ...],
) -> None:
    journal, provider = Journal(), FakeProvider(intents[0].plan)
    lease = Lease(tmp_path, intents, journal)
    issue(lease, provider)
    for intent in intents:
        (tmp_path / f"{intent.role}-entered.json").unlink()  # Synthetic corruption only.
    journal.values = [row for row in journal.values if row["kind"] != "entered"]
    lease.cleanup(cast(Provider, provider), require_issuer_stopped=lambda: None)
    assert "not-submitted" not in json.dumps(read_private(tmp_path / "closed.json"))
    assert len(provider.deleted) == len(PERMISSIONS)


def test_uuid4_and_unapproved_lifetime_are_rejected(
    plan: Plan, intents: tuple[Intent, ...]
) -> None:
    with pytest.raises((ValueError, RuntimeError)):
        replace(plan, run_id=str(uuid.uuid4()))
    with pytest.raises((ValueError, RuntimeError)):
        replace(plan, nonce=str(uuid.uuid4()))
    with pytest.raises((ValueError, RuntimeError)):
        replace(intents[0], expires_at="2027-10-29T00:00:00Z")


def test_real_prerequisite_helper_uses_native_reconstruction_only(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = installed_module("isolated_public_ca_recovery")
    fixture, source = Mock(), Mock()
    prepare = Mock(return_value=(fixture, ["synthetic-tenant"], {"actual": "native-helper-result"}))
    verify = Mock()
    monkeypatch.setattr(module.restore, "source", prepare)
    monkeypatch.setattr(module.restore, "verify_reconstruction", verify)
    result = module.reconstruct(source, tmp_path)
    prepare.assert_called_once_with(source, tmp_path, full_history=True, live_storage=None)
    fixture.fault.assert_called_once_with("none")
    fixture.start.assert_called_once_with()
    verify.assert_called_once_with(fixture, result[2])
    assert result[0] is fixture


def test_failure_stop_ignores_unrelated_actor_failure_but_checks_destination(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    plan: Plan,
) -> None:
    module = installed_module("isolated_public_ca_recovery")
    recovery = object.__new__(module.IsolatedRecovery)
    destination = {"id": "1" * 64, "name": "owned-destination", "owner": "owner", "image": "image"}
    recovery.context = {
        "actors": {"destination": destination},
        "guest_program_sha256": hashlib.sha256(b"guest").hexdigest(),
    }
    recovery.program, recovery.plan, recovery.directory = "guest", plan, tmp_path
    recovery.fixture = Mock(environment={})
    write_private(tmp_path / "isolation-context.json", recovery.context)
    monkeypatch.setattr(module, "daemon_identity", Mock())
    inspect = Mock(return_value={**destination, "running": True})
    monkeypatch.setattr(module.owned, "inspect", inspect)
    recovery._identity = Mock(side_effect=ValueError("MinIO died"))
    dispatch = Mock(return_value={"stopped": True})
    recovery._dispatch = dispatch
    assert recovery.call("stop_failed") == {"stopped": True}
    recovery._identity.assert_not_called()
    inspect.assert_called_once_with({}, destination["id"])
    inspect.return_value["owner"] = "foreign"
    with pytest.raises(ValueError):
        recovery.call("stop_failed")
    assert dispatch.call_count == 1


def test_topology_cannot_accept_another_daemon_or_host_network_guest(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    plan: Plan,
) -> None:
    module = installed_module("isolated_public_ca_recovery")
    fixture = Mock(environment={"DOCKER_HOST": plan.docker_endpoint})
    fixture.command.return_value = b'{"different":"daemon"}'
    with pytest.raises(ValueError, match="daemon"):
        module.daemon_identity(fixture, plan)
    monkeypatch.setattr(module, "daemon_identity", Mock(return_value={"pinned": True}))
    fixture.command.return_value = b"host\n"
    with pytest.raises(ValueError, match="native network path"):
        module.topology(fixture, {"destination": {"id": "1" * 64}}, plan)


def test_mixed_role_lifetimes_are_rejected_before_any_authentication(
    plan: Plan,
    intents: tuple[Intent, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import m3_11_isolation_dns as dns  # noqa: PLC0415 - scoped boundary replacement

    mixed = (
        replace(intents[0], requested_at="2026-10-29T00:00:30Z", expires_at="2026-10-29T04:00:30Z"),
        *intents[1:],
    )
    client = Mock(side_effect=AssertionError("no provider calls"))
    monkeypatch.setattr(dns, "CloudflareClient", client)
    with pytest.raises(ValueError, match="bindings differ"):
        dns.authenticate(
            plan,
            mixed,
            Readers(SECRET, SECRET + "1", SECRET + "2"),
            expected_ids={
                role: hashlib.sha256(role.encode()).hexdigest()[:32] for role in PERMISSIONS
            },
            now=NOW,
        )
    client.assert_not_called()


def test_initial_start_rechecks_time_after_identity_io(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    intents: tuple[Intent, ...],
) -> None:
    module = installed_module("isolated_public_ca_recovery")
    recovery = object.__new__(module.IsolatedRecovery)
    recovery.intents = intents
    clock = [NOW]
    datetime_double = Mock()
    datetime_double.now.side_effect = lambda zone: clock[0]
    monkeypatch.setattr(module, "datetime", datetime_double)
    recovery.require_cleanup_armed = Mock()
    recovery._identity = Mock(
        side_effect=lambda: clock.__setitem__(0, datetime(2026, 10, 29, 0, 11, tzinfo=UTC))
    )
    recovery.fixture = Mock()
    with pytest.raises(ValueError, match="cleanup reserve"):
        recovery.call("start")
    recovery.fixture.command.assert_not_called()


@pytest.mark.parametrize("contrary", ["remote-created", "private-secret", "remote-issued"])
def test_not_submitted_readback_rejects_all_contrary_creation_evidence(
    tmp_path: Path,
    intents: tuple[Intent, ...],
    contrary: str,
) -> None:
    from scripts.m3_11_unattended.model import digest  # noqa: PLC0415 - explicit test fixture hash

    journal, provider = Journal(), FakeProvider(intents[0].plan)
    provider.fail_create = "audit"
    lease = Lease(tmp_path, intents, journal)
    with pytest.raises(OSError):
        issue(lease, provider)
    # Deliberately forged synthetic closure tests the independent validator,
    # not the already-stricter cleanup producer. Never a live repair path.
    (tmp_path / "audit-entered.json").unlink()
    journal.values = [row for row in journal.values if row["kind"] != "entered"]
    if contrary == "remote-created":
        journal.persist(
            lease._record(
                "created", {"intent_sha256": intents[0].sha256, "credential_id": "0" * 32}
            )
        )
    elif contrary == "private-secret":
        write_private(tmp_path / "audit.credential", {"value": SECRET})
    else:
        journal.persist(
            lease._record(
                "issued",
                {
                    "ids": {
                        role: hashlib.sha256(role.encode()).hexdigest()[:32] for role in PERMISSIONS
                    }
                },
            )
        )
    value: dict[str, object] = {
        "plan_sha256": lease.plan_sha256,
        "roles": {role: {"creation": "not-submitted"} for role in PERMISSIONS},
    }
    journal.persist(lease._record("closed", value))
    write_private(tmp_path / "closed.json", value)
    with pytest.raises(ValueError, match="contrary creation"):
        lease.independent_readback(
            cast(Provider, provider), expected=digest(value), require_issuer_stopped=lambda: None
        )
