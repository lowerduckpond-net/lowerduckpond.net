"""Explicit synthetic lease policies and complete pre-creation obligations."""

from __future__ import annotations

import dataclasses
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import override

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import connect_api
from scripts.m3_11_unattended import inventory as lease_inventory
from scripts.m3_11_unattended.connect_api import Connect, ConnectResponseError, Response
from scripts.m3_11_unattended.connect_diagnostics import failure_chain
from scripts.m3_11_unattended.inventory import (
    ConnectInventory,
    LocalInventory,
    _collect,
    fact,
    require_confirmation,
    title,
)
from scripts.m3_11_unattended.lifecycle import CreationRecorder, LeaseLifecycle
from scripts.m3_11_unattended.model import (
    PROVIDERS,
    ROLES,
    AuthorityGeneration,
    Credential,
    Intent,
    LeaseManifest,
    LeasePolicy,
    LifecycleError,
    ProviderKind,
    Targets,
    digest,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState

from .test_m3_11_unattended_lifecycle import ProviderDouble

NOW = datetime(2026, 10, 10, tzinfo=UTC)
TARGETS = Targets("nyc3", "test-archive", "test-backup", "a" * 32, "b" * 32, "c" * 32, "d" * 32)
SOURCE = "1" * 40


def policy() -> LeasePolicy:
    return LeasePolicy(
        approved_at=stamp(NOW - timedelta(hours=1)),
        start_before=stamp(NOW + timedelta(hours=1)),
        issuance_before=stamp(NOW + timedelta(hours=3)),
        credential_lifetime_seconds=7 * 24 * 3600,
        cleanup_reserve_seconds=2 * 24 * 3600,
        retain_after_failure=True,
        approval_reference="SYNTHETIC-TEST-ONLY-no-live-approval",
    )


def generation(role: str, generation_id: str) -> AuthorityGeneration:
    return AuthorityGeneration(
        generation_id=generation_id,
        role=role,
        targets_sha256=digest(dataclasses.asdict(TARGETS)),
        principals={
            "spaces": "synthetic-team-a",
            "cloudflare-account": TARGETS.account_id,
            "cloudflare-user": TARGETS.user_id,
        },
        fingerprints={provider: digest([role, provider]) for provider in PROVIDERS},
        expires_at={provider: stamp(NOW + timedelta(days=30)) for provider in PROVIDERS},
        connect_expires_at=stamp(NOW + timedelta(days=30)),
        introduced_at=stamp(NOW),
        rotation_due_at=stamp(NOW.replace(month=11)),
    )


def manifest() -> LeaseManifest:
    selected_policy = policy()
    lease_id, generation_id = str(uuid.uuid7()), str(uuid.uuid7())
    creator, cleanup = generation("provision", generation_id), generation("cleanup", generation_id)
    intents = []
    for role in sorted(ROLES):
        provider: ProviderKind = (
            "spaces"
            if role in {"archive", "backup", "operator"}
            else "cloudflare-user"
            if role == "page-rules"
            else "cloudflare-account"
        )
        intents.append(
            Intent(
                run_id=lease_id,
                role=role,
                source_revision=SOURCE,
                helper_revision=SOURCE,
                provider=provider,
                cleanup_authority_sha256=cleanup.fingerprints[provider],
                name=f"ldp-m311-{uuid.UUID(lease_id).hex}-{role}",
                requested_at=stamp(NOW),
                create_before=selected_policy.issuance_before,
                deadline=stamp(selected_policy.deadline(NOW)),
                scope={"synthetic_role": role},
                baseline_ids=(),
                targets=TARGETS,
                policy=selected_policy,
            )
        )
    return LeaseManifest(
        lease_id,
        SOURCE,
        SOURCE,
        stamp(NOW),
        selected_policy,
        creator,
        cleanup,
        TARGETS,
        tuple(intents),
    )


@pytest.mark.parametrize(
    "field",
    [
        "issuance_before",
        "cleanup_reserve_seconds",
        "credential_lifetime_seconds",
        "approval_reference",
    ],
)
def test_missing_policy_value_never_receives_a_default(field: str) -> None:
    raw = policy().document()
    del raw[field]
    with pytest.raises((ValueError, LifecycleError)):
        LeasePolicy.parse(raw)


def test_synthetic_policy_requires_separate_exact_approval_binding() -> None:
    selected = policy()
    with pytest.raises(LifecycleError, match="unapproved"):
        selected.require_start(now=NOW, approved_sha256="0" * 64)
    selected.require_start(now=NOW, approved_sha256=selected.sha256)
    with pytest.raises(LifecycleError, match="elapsed"):
        selected.require_start(now=NOW + timedelta(hours=2), approved_sha256=selected.sha256)


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.2, "172800"])
def test_reserve_must_be_an_explicit_positive_integer(value: object) -> None:
    raw = policy().document()
    raw["cleanup_reserve_seconds"] = value
    with pytest.raises(LifecycleError):
        LeasePolicy.parse(raw)


def test_policy_parsing_preserves_original_approval_document() -> None:
    raw = policy().document()
    before = digest(raw)
    assert LeasePolicy.parse(raw).document() == raw
    assert digest(raw) == before


def test_whole_manifest_includes_all_roles_and_exact_lifetimes() -> None:
    original = manifest()
    restored = LeaseManifest.parse(original.document())
    assert restored.sha256 == original.sha256
    assert {entry.role for entry in restored.intents} == ROLES
    assert len({entry.deadline for entry in restored.intents}) == 1
    assert all(entry.policy == original.policy for entry in restored.intents)


def test_partial_manifest_cannot_authorize_any_creation() -> None:
    original = manifest()
    with pytest.raises(LifecycleError, match="incomplete"):
        dataclasses.replace(original, intents=original.intents[:-1])


def test_missing_provider_expiry_has_no_inherited_default() -> None:
    raw = manifest().cleanup.document()
    raw["expires_at"] = {"spaces": stamp(NOW + timedelta(days=30))}
    with pytest.raises(LifecycleError, match="incomplete"):
        AuthorityGeneration.parse(raw)


def test_cleanup_must_cover_the_explicit_reserve() -> None:
    original = manifest()
    expiry = stamp(original.policy.deadline(NOW) + timedelta(days=1))
    short = dataclasses.replace(original.cleanup, expires_at=dict.fromkeys(PROVIDERS, expiry))
    with pytest.raises(LifecycleError, match="cover"):
        dataclasses.replace(original, cleanup=short)


def test_wrong_team_authentication_cannot_establish_handover() -> None:
    previous = manifest().cleanup
    wrong = dataclasses.replace(
        previous,
        generation_id=str(uuid.uuid7()),
        principals={**previous.principals, "spaces": "synthetic-team-b"},
    )
    with pytest.raises(LifecycleError, match="principal"):
        wrong.require_same_principal(previous)


def test_same_principal_is_independent_of_secret_fingerprint() -> None:
    previous = manifest().cleanup
    replacement = dataclasses.replace(
        previous,
        generation_id=str(uuid.uuid7()),
        fingerprints={provider: digest(["replacement", provider]) for provider in PROVIDERS},
    )
    replacement.require_same_principal(previous)
    assert replacement.fingerprints != previous.fingerprints
    # Positive native readback is still required by the later handover operation;
    # this metadata comparison alone is not permission to delete or issue.


def test_legacy_intent_bytes_and_hash_do_not_acquire_lease_fields() -> None:
    original = manifest().intents[0]
    legacy = dataclasses.replace(
        original,
        policy=None,
        create_before=stamp(NOW + timedelta(minutes=5)),
        deadline=stamp(NOW + timedelta(hours=14)),
    )
    assert "policy" not in legacy.document()
    restored = Intent.parse(legacy.document())
    assert restored.document() == legacy.document()
    assert restored.sha256 == legacy.sha256


class ConnectDouble(Connect):
    def __init__(self, vault: str = "v" * 26) -> None:
        super().__init__("https://connect.example.invalid", "synthetic-client-canary")
        self.items: dict[str, dict[str, object]] = {}
        self.vault = vault
        self.posts = 0
        self.lose_reply = False
        self.hidden = False
        self.fail_list = False

    @override
    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if method == "GET":
            assert path == "/v1/vaults/" + self.vault + "/items"
            if self.fail_list:
                return Response(503, {})
            return Response(200, [] if self.hidden else list(self.items.values()))
        assert method == "POST" and body is not None
        self.posts += 1
        item_id = f"{self.posts:026d}"
        self.items[item_id] = {**deepcopy(body), "id": item_id}
        if self.lose_reply:
            raise LifecycleError("synthetic lost response")
        return Response(201, self.items[item_id])

    @override
    def item(self, vault: str, item: str) -> dict[str, object]:
        assert vault == self.vault
        return deepcopy(self.items[item])


class VisibilityClock:
    """Only elapsed time and the external HTTP responses are controlled below."""

    def __init__(self) -> None:
        self.seconds = 0.0

    def monotonic(self) -> float:
        return self.seconds

    def sleep(self, seconds: float) -> None:
        assert seconds > 0
        self.seconds += seconds


class PublicationConnect(ConnectDouble):
    def __init__(self) -> None:
        super().__init__()
        self.read_responses: list[Response] = []
        self.repeated_response: Response | None = None
        self.reads: list[tuple[str, float]] = []
        self.lose_slots: set[str] = set()

    @override
    def item(self, vault: str, item: str) -> dict[str, object]:
        # Exercise real identity/status validation, not ConnectDouble's shortcut.
        return Connect.item(self, vault, item)

    @override
    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if method == "GET" and not path.endswith("/items"):
            self.reads.append((path, self._request_timeout))
            if self.read_responses:
                return self.read_responses.pop(0)
            if self.repeated_response is not None:
                return self.repeated_response
            return Response(200, deepcopy(self.items[path.rsplit("/", 1)[1]]))
        response = super().request(method, path, body)
        if method == "POST" and body is not None:
            slot = next(
                (slot for slot in self.lose_slots if str(body["title"]).endswith(slot)), None
            )
            if slot is not None:
                self.lose_slots.remove(slot)
                raise LifecycleError("synthetic committed POST with lost reply")
        return response


@pytest.fixture
def visibility_clock(monkeypatch: pytest.MonkeyPatch) -> VisibilityClock:
    clock = VisibilityClock()
    monkeypatch.setattr(connect_api, "time", clock)
    return clock


def test_acknowledged_post_tolerates_only_bounded_exact_item_visibility(
    tmp_path: Path, visibility_clock: VisibilityClock
) -> None:
    client = PublicationConnect()
    client.read_responses = [Response(404, None), Response(404, None)]
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    selected = manifest()
    record = fact(selected, "manifest", selected.document())
    inventory.publish(record)
    assert client.posts == 1
    assert len(client.reads) == 3  # noqa: PLR2004 - two missing reads then exact visibility
    assert len({path for path, _ in client.reads}) == 1
    assert visibility_clock.seconds == 2  # noqa: PLR2004 - two one-second waits
    assert [budget for _, budget in client.reads] == [30, 29, 28]
    assert inventory.records() == [record]
    assert client._request_timeout == connect_api.TIMEOUT_SECONDS
    # Shared visibility cannot satisfy the distinct independent confirmation gate.
    with pytest.raises(LifecycleError, match="confirmation is unavailable"):
        require_confirmation(inventory, selected, independent_server_id="s" * 26)


@pytest.mark.parametrize("budget", [30, 2.5])
def test_visibility_exhaustion_keeps_pending_bytes_and_reconciles_without_post(
    tmp_path: Path, visibility_clock: VisibilityClock, budget: float
) -> None:
    client = PublicationConnect()
    client.repeated_response = Response(404, None)
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    selected = manifest()
    record = fact(selected, "manifest", selected.document())
    with pytest.raises(ConnectResponseError) as captured, client.timeout_budget(budget):
        inventory.publish(record)
    assert visibility_clock.seconds == budget
    assert len(client.reads) <= connect_api.VISIBILITY_READ_ATTEMPTS
    assert [remaining for _, remaining in client.reads] == sorted(
        [remaining for _, remaining in client.reads], reverse=True
    )
    assert captured.value.response == {
        "status": 404,
        "check": "item-status",
        "body_type": "null",
        "visibility_wait": {
            "attempts": len(client.reads),
            "timeout_ms": budget * 1000,
            "elapsed_ms": budget * 1000,
        },
    }
    pending = next(inventory.spool.iterdir())
    before = pending.read_bytes(), pending.stat().st_mtime_ns
    assert read_private(pending) == record
    restarted = ConnectInventory(client, client.vault, spool=inventory.spool)
    client.hidden = True
    with pytest.raises(LifecycleError, match="unobserved"):
        restarted.publish(record)
    client.hidden, client.repeated_response = False, None
    restarted.publish(record)
    assert client.posts == 1
    assert (pending.read_bytes(), pending.stat().st_mtime_ns) == before


def test_visibility_budget_includes_http_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, visibility_clock: VisibilityClock
) -> None:
    client = PublicationConnect()
    client.repeated_response = Response(404, None)
    request = client.request

    def delayed_http(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        response = request(method, path, body)
        if method == "GET" and not path.endswith("/items"):
            visibility_clock.seconds += min(0.25, client._request_timeout)
        return response

    monkeypatch.setattr(client, "request", delayed_http)
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    selected = manifest()
    with pytest.raises(ConnectResponseError), client.timeout_budget(2.6):
        inventory.publish(fact(selected, "manifest", selected.document()))
    assert visibility_clock.seconds == 2.6  # noqa: PLR2004 - one aggregate caller budget
    assert [budget for _, budget in client.reads] == pytest.approx([2.6, 1.35, 0.1])
    assert client.posts == 1


@pytest.mark.parametrize(
    "response",
    [Response(401, None), Response(403, None), Response(200, []), Response(200, {"id": "x" * 26})],
)
@pytest.mark.parametrize("initial_missing", [False, True])
def test_visibility_does_not_retry_denial_or_bad_identity(
    tmp_path: Path, visibility_clock: VisibilityClock, response: Response, initial_missing: bool
) -> None:
    client = PublicationConnect()
    client.read_responses = ([Response(404, None)] if initial_missing else []) + [response]
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    selected = manifest()
    with pytest.raises(ConnectResponseError):
        inventory.publish(fact(selected, "manifest", selected.document()))
    assert client.posts == 1
    assert len(client.reads) == 1 + initial_missing
    assert visibility_clock.seconds == initial_missing
    assert len(list(inventory.spool.iterdir())) == 1


def test_visible_wrong_content_is_not_treated_as_visibility_lag(
    tmp_path: Path, visibility_clock: VisibilityClock
) -> None:
    client = PublicationConnect()
    client.read_responses = [
        Response(
            200,
            {
                "id": f"{1:026d}",
                "vault": {"id": client.vault},
                "category": "PASSWORD",
            },
        )
    ]
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    selected = manifest()
    with pytest.raises(LifecycleError, match="unavailable or changed"):
        inventory.publish(fact(selected, "manifest", selected.document()))
    assert client.posts == len(client.reads) == 1
    assert visibility_clock.seconds == 0


def confirmation(selected: LeaseManifest) -> dict[str, object]:
    return fact(
        selected,
        "confirmed",
        {
            "helper_revision": SOURCE,
            "independent_server_id": "s" * 26,
            "observed_at": stamp(NOW),
            "github_run_id": 12345,
            "github_run_attempt": 1,
            "cleanup_access_expires_at": stamp(NOW + timedelta(days=30)),
        },
    )


@pytest.mark.parametrize("offsets", [(0, 1), (1, 2)])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("adapter", ["connect", "local"])
def test_each_future_confirmation_blocks_provider_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offsets: tuple[int, int],
    reverse: bool,
    adapter: str,
) -> None:
    # Only the clock and external inventory contents are modeled. Actual readers,
    # equivalence reduction and the issuance authorization all execute.
    monkeypatch.setattr(
        lease_inventory, "datetime", SimpleNamespace(now=lambda _tz: NOW), raising=False
    )
    case = LeaseCase(tmp_path)
    observations = []
    for index, seconds in enumerate(offsets):
        record = confirmation(case.manifest)
        payload = record["payload"]
        assert isinstance(payload, dict)
        payload.update(
            observed_at=stamp(NOW + timedelta(seconds=seconds)), github_run_id=12345 + index
        )
        observations.append(record)
    if reverse:
        observations.reverse()
    if adapter == "connect":
        client = ConnectDouble()
        inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
        inventory.publish(fact(case.manifest, "manifest", case.manifest.document()))
        for record in observations:
            client.request(
                "POST",
                f"/v1/vaults/{client.vault}/items",
                {
                    "title": title(record),
                    "category": "SECURE_NOTE",
                    "tags": [lease_inventory.TAG],
                    "fields": [
                        {
                            "id": "notesPlain",
                            "type": "STRING",
                            "purpose": "NOTES",
                            "label": "notesPlain",
                            "value": canonical_bytes(record).decode(),
                        }
                    ],
                },
            )
        case.lifecycle.inventory = inventory
    else:
        for index, record in enumerate(observations):
            write_private(case.inventory.directory / f"observation-{index}.json", record)
    with pytest.raises(LifecycleError, match="confirmation has the wrong binding"):
        case.issue()
    assert sum(provider.creates for provider in case.providers.values()) == 0


@pytest.mark.parametrize("existing", [False, True])
def test_future_publication_is_rejected_before_post_or_equivalent_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    monkeypatch.setattr(
        lease_inventory, "datetime", SimpleNamespace(now=lambda _tz: NOW), raising=False
    )
    selected = manifest()
    client = ConnectDouble()
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    inventory.publish(fact(selected, "manifest", selected.document()))
    if existing:
        inventory.publish(confirmation(selected))
    record = confirmation(selected)
    payload = record["payload"]
    assert isinstance(payload, dict)
    payload["observed_at"] = stamp(NOW + timedelta(seconds=1))
    posts = client.posts
    pending = sorted(inventory.spool.iterdir())
    with pytest.raises(LifecycleError, match="confirmation has the wrong binding"):
        inventory.publish(record)
    assert client.posts == posts and sorted(inventory.spool.iterdir()) == pending


@pytest.mark.parametrize("age", [timedelta(), timedelta(days=3)])
def test_confirmation_upper_bound_allows_present_and_older_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, age: timedelta
) -> None:
    monkeypatch.setattr(
        lease_inventory, "datetime", SimpleNamespace(now=lambda _tz: NOW + age), raising=False
    )
    selected = manifest()
    client = ConnectDouble()
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    inventory.publish(fact(selected, "manifest", selected.document()))
    inventory.publish(confirmation(selected))
    require_confirmation(inventory, selected, independent_server_id="s" * 26)


def test_independent_observations_with_distinct_provenance_are_one_confirmation() -> None:
    selected = manifest()
    first = confirmation(selected)
    second = deepcopy(first)
    payload = second["payload"]
    assert isinstance(payload, dict)
    payload.update(observed_at=stamp(NOW + timedelta(seconds=1)), github_run_id=12346)
    original = deepcopy([first, second])
    manifest_fact = fact(selected, "manifest", selected.document())
    for records in ([first, second, manifest_fact], [manifest_fact, second, first]):
        result = _collect(records)
        assert [row for row in result if row["slot"] == "confirmed"] == [first]
    assert [first, second] == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("observed_at", "2026-10-09T00:00:00Z"),
        ("github_run_id", 0),
        ("cleanup_access_expires_at", "2026-10-11T00:00:00Z"),
        ("helper_revision", "f" * 40),
        ("independent_server_id", "t" * 26),
    ],
)
def test_equivalence_cannot_hide_an_invalid_or_conflicting_observation(
    field: str, value: object
) -> None:
    selected = manifest()
    first = confirmation(selected)
    second = deepcopy(first)
    payload = second["payload"]
    assert isinstance(payload, dict)
    payload[field] = value
    with pytest.raises(LifecycleError):
        _collect([fact(selected, "manifest", selected.document()), first, second])


def test_local_manifest_visibility_is_not_independent_confirmation(tmp_path: Path) -> None:
    selected = manifest()
    inventory = LocalInventory(tmp_path / "facts")
    inventory.publish(fact(selected, "manifest", selected.document()))
    with pytest.raises(LifecycleError, match="confirmation is unavailable"):
        require_confirmation(inventory, selected, independent_server_id="s" * 26)
    inventory.publish(confirmation(selected))
    require_confirmation(inventory, selected, independent_server_id="s" * 26)
    with pytest.raises(LifecycleError, match="wrong binding"):
        require_confirmation(inventory, selected, independent_server_id="t" * 26)


def test_confirmation_cannot_authorize_a_changed_manifest(tmp_path: Path) -> None:
    selected = manifest()
    inventory = LocalInventory(tmp_path / "facts")
    inventory.publish(fact(selected, "manifest", selected.document()))
    changed = dataclasses.replace(
        selected,
        policy=dataclasses.replace(
            selected.policy, approval_reference="different-synthetic-approval"
        ),
        intents=tuple(
            dataclasses.replace(
                i,
                policy=dataclasses.replace(
                    selected.policy, approval_reference="different-synthetic-approval"
                ),
            )
            for i in selected.intents
        ),
    )
    inventory.publish(confirmation(changed))
    with pytest.raises(LifecycleError, match="wrong binding"):
        require_confirmation(inventory, selected, independent_server_id="s" * 26)


def test_lost_connect_reply_is_reconciled_without_another_post(tmp_path: Path) -> None:
    selected = manifest()
    client = ConnectDouble()
    inventory = ConnectInventory(client, "v" * 26, spool=tmp_path / "spool")
    record = fact(selected, "manifest", selected.document())
    client.lose_reply = True
    with pytest.raises(LifecycleError, match="lost response"):
        inventory.publish(record)
    restarted = ConnectInventory(client, "v" * 26, spool=tmp_path / "spool")
    restarted.publish(record)
    assert restarted.records() == [record]
    assert client.posts == 1


def test_delayed_visibility_preserves_uncertainty_without_reposting(tmp_path: Path) -> None:
    selected = manifest()
    client = ConnectDouble()
    inventory = ConnectInventory(client, "v" * 26, spool=tmp_path / "spool")
    record = fact(selected, "manifest", selected.document())
    client.lose_reply = True
    with pytest.raises(LifecycleError):
        inventory.publish(record)
    client.hidden = True
    with pytest.raises(LifecycleError, match="unobserved"):
        inventory.publish(record)
    assert client.posts == 1
    client.hidden = False
    inventory.publish(record)
    assert client.posts == 1


def test_failed_listing_is_never_an_empty_inventory(tmp_path: Path) -> None:
    client = ConnectDouble()
    client.fail_list = True
    inventory = ConnectInventory(client, "v" * 26, spool=tmp_path / "spool")
    selected = manifest()
    with pytest.raises(LifecycleError, match="incomplete or unavailable"):
        inventory.publish(fact(selected, "manifest", selected.document()))
    assert client.posts == 0


def test_repeat_facts_are_bounded_and_conflicting_identity_is_rejected(tmp_path: Path) -> None:
    selected = manifest()
    inventory = LocalInventory(tmp_path / "facts")
    intent = selected.intents[0]
    record = fact(
        selected,
        "created:" + intent.role,
        {"intent_sha256": intent.sha256, "credential_id": "synthetic-key-one"},
    )
    for _ in range(5):
        inventory.publish(record)
    assert inventory.records() == [record]
    changed = fact(
        selected,
        "created:" + intent.role,
        {"intent_sha256": intent.sha256, "credential_id": "synthetic-key-two"},
    )
    with pytest.raises(LifecycleError, match="cannot be replaced"):
        inventory.publish(changed)


def test_secret_field_cannot_enter_inventory(tmp_path: Path) -> None:
    selected = manifest()
    inventory = LocalInventory(tmp_path / "facts")
    record = fact(
        selected,
        "created:archive",
        {"intent_sha256": selected.intents[0].sha256, "credential_id": "synthetic-key-one"},
    )
    record["secret"] = "synthetic-export-canary-9fe8"  # noqa: S105 - deliberate export canary
    with pytest.raises((ValueError, LifecycleError)) as raised:
        inventory.publish(record)
    assert "synthetic-export-canary-9fe8" not in str(raised.value)
    assert inventory.records() == []


class LeaseProviderDouble(ProviderDouble):
    def __init__(self, kind: ProviderKind, authority: str) -> None:
        super().__init__()
        self.kind, self.authority_sha256 = kind, authority

    @override
    def create(self, intent: Intent, *, record: CreationRecorder) -> Credential:
        self.on_create()
        self.creates += 1
        selected = "synthetic-" + intent.role
        secret = "SYNTHETIC-PRIVATE-CANARY-" + intent.role
        metadata: dict[str, object] = {
            "id": selected,
            "name": intent.name,
            "created_at": intent.requested_at,
            "scope": {} if self.wrong_scope else intent.scope,
            "status": "active",
            "expires_at": intent.deadline if intent.provider != "spaces" else None,
        }
        self.items[selected] = metadata
        if self.lose_response:
            raise LifecycleError("synthetic provider lost creation response")
        record(selected, secret)
        return Credential(selected, secret, metadata)


class LeaseCase:
    def __init__(self, root: Path) -> None:
        self.manifest = manifest()
        self.inventory = LocalInventory(root / "facts")
        self.state = LeaseState(root / "private-lease")
        self.providers = {
            kind: LeaseProviderDouble(kind, self.manifest.creator.fingerprints[kind])
            for kind in PROVIDERS
        }
        self.cleanup_providers = {
            kind: LeaseProviderDouble(kind, self.manifest.cleanup.fingerprints[kind])
            for kind in PROVIDERS
        }
        for kind, cleanup_provider in self.cleanup_providers.items():
            cleanup_provider.items = self.providers[kind].items
        self.lifecycle = LeaseLifecycle(
            self.manifest, self.inventory, self.state, providers=self.providers, clock=lambda: NOW
        )
        self.lifecycle.prepare()

    def confirm(self) -> None:
        self.inventory.publish(confirmation(self.manifest))

    def issue(self) -> dict[str, Credential]:
        return self.lifecycle.issue(
            writer_sha256="a" * 64,
            approved_policy_sha256=self.manifest.policy.sha256,
            independent_server_id="s" * 26,
        )


def test_no_provider_create_until_whole_manifest_is_independently_confirmed(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    with pytest.raises(LifecycleError, match="confirmation is unavailable"):
        case.issue()
    assert sum(provider.creates for provider in case.providers.values()) == 0
    case.confirm()
    credentials = case.issue()
    assert set(credentials) == ROLES
    assert sum(provider.creates for provider in case.providers.values()) == len(ROLES)
    assert "issuer-stopped" in case.lifecycle.records()
    assert "SYNTHETIC-PRIVATE-CANARY" not in str(case.inventory.records())


def test_completed_or_interrupted_issuer_cannot_be_replayed(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    restarted = LeaseLifecycle(
        case.manifest, case.inventory, case.state, providers=case.providers, clock=lambda: NOW
    )
    with pytest.raises(LifecycleError, match="replayed"):
        restarted.issue(
            writer_sha256="b" * 64,
            approved_policy_sha256=case.manifest.policy.sha256,
            independent_server_id="s" * 26,
        )
    assert sum(provider.creates for provider in case.providers.values()) == len(ROLES)


def test_death_after_durable_claim_never_adopts_the_interrupted_issuer(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.state.claim_issuer(writer_sha256="b" * 64)
    with pytest.raises(LifecycleError, match="replayed"):
        case.issue()
    assert sum(provider.creates for provider in case.providers.values()) == 0
    assert "issuer-stopped" not in case.lifecycle.records()


def test_preparation_failure_and_lost_stop_publication_reconcile_without_reissuing(
    tmp_path: Path, visibility_clock: VisibilityClock
) -> None:
    case = LeaseCase(tmp_path)
    client = PublicationConnect()
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "spool")
    case.lifecycle.inventory = inventory
    client.repeated_response = Response(404, None)
    with pytest.raises(ConnectResponseError):
        case.lifecycle.prepare(writer_sha256="a" * 64)
    client.repeated_response = None
    client.lose_slots = {"issuer-stopped"}
    with pytest.raises(LifecycleError, match="evidence remains unpublished") as captured:
        case.lifecycle.abandon_prepared()
    assert failure_chain(captured.value)["related_failures"]
    stopped = case.state.directory / "issuer-stopped.json"
    before = stopped.read_bytes(), stopped.stat().st_mtime_ns
    pending = {path: path.read_bytes() for path in inventory.spool.iterdir()}
    posts = client.posts
    case.lifecycle.clock = lambda: NOW + timedelta(seconds=30)
    case.lifecycle.abandon_prepared()
    assert (stopped.read_bytes(), stopped.stat().st_mtime_ns) == before
    assert {path: path.read_bytes() for path in inventory.spool.iterdir()} == pending
    assert client.posts == posts
    assert case.lifecycle.records()["issuer-stopped"]["payload"] == read_private(stopped)
    assert sum(provider.creates for provider in case.providers.values()) == 0
    assert not list(case.state.directory.glob("submitting-*.json"))
    with pytest.raises(LifecycleError, match="original active invocation"):
        case.state.submitting(case.manifest.intents[0], writer_sha256="a" * 64)
    with pytest.raises(LifecycleError, match="replayed"):
        case.lifecycle.prepare(writer_sha256="a" * 64)
    case.lifecycle.request_close("finish")
    assert all(row.status == "verified" for row in case.lifecycle.reconcile(case.cleanup_providers))


def test_original_stop_proof_survives_secret_cleanup_and_rejects_another_writer(
    tmp_path: Path,
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    stopped = case.state.directory / "issuer-stopped.json"
    before = stopped.read_bytes(), stopped.stat().st_mtime_ns
    case.lifecycle.request_close("finish")
    assert all(row.status == "verified" for row in case.lifecycle.reconcile(case.cleanup_providers))
    # Model later private-secret disposal after verified cleanup. Its original
    # historical retention proof must not be rebuilt from the current files.
    for path in case.state.directory.glob("credential-*.json"):
        path.unlink()
    assert not list(case.state.directory.glob("credential-*.json"))
    proof = case.state.finish_issuer(
        writer_sha256="a" * 64, stopped_at=stamp(NOW + timedelta(days=1))
    )
    assert proof["retained_roles"] == sorted(ROLES)
    assert (stopped.read_bytes(), stopped.stat().st_mtime_ns) == before
    with pytest.raises(LifecycleError, match="original invocation"):
        case.state.finish_issuer(writer_sha256="b" * 64, stopped_at=stamp(NOW))
    with pytest.raises(LifecycleError, match="original active invocation"):
        case.state.submitting(case.manifest.intents[0], writer_sha256="a" * 64)


@pytest.mark.parametrize(
    "field,value",
    [
        ("writer_sha256", "b" * 64),
        ("retained_roles", ["archive"]),
        ("retained_roles", ["unknown"]),
        ("retained_roles", ["archive", "archive"]),
        ("stopped_at", "2099-01-01T00:00:00Z"),
    ],
)
def test_stop_proof_reconciliation_rejects_changed_proof(
    tmp_path: Path, field: str, value: object
) -> None:
    case = LeaseCase(tmp_path)
    case.state.claim_issuer(writer_sha256="a" * 64)
    proof = case.state.finish_issuer(writer_sha256="a" * 64, stopped_at=stamp(NOW))
    proof[field] = value
    path = case.state.directory / "issuer-stopped.json"
    path.write_bytes(canonical_bytes(proof))
    with pytest.raises(LifecycleError, match="stop proof differs"):
        case.state.finish_issuer(writer_sha256="a" * 64, stopped_at=stamp(NOW))


def test_stop_proof_cannot_be_reconciled_under_a_changed_manifest_binding(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.state.claim_issuer(writer_sha256="a" * 64)
    case.state.finish_issuer(writer_sha256="a" * 64, stopped_at=stamp(NOW))
    path = case.state.directory / "issuer.json"
    original = read_private(path)
    path.write_bytes(canonical_bytes({**original, "manifest_sha256": "b" * 64}))
    with pytest.raises(LifecycleError, match="differs from the original invocation"):
        case.state.finish_issuer(writer_sha256="a" * 64, stopped_at=stamp(NOW))


def test_lost_creation_response_retains_uncertainty_and_stops_the_remaining_roles(
    tmp_path: Path,
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.providers["spaces"].lose_response = True
    with pytest.raises(LifecycleError, match="lost creation response"):
        case.issue()
    records = case.lifecycle.records()
    assert sum(provider.creates for provider in case.providers.values()) == 1
    assert "created:archive" not in records
    assert "not-submitted:archive" not in records
    assert "close-provisioning-failed" in records
    assert sum(slot.startswith("not-submitted:") for slot in records) == len(ROLES) - 1
    assert "issuer-stopped" in records
    with pytest.raises(LifecycleError):
        case.issue()
    assert sum(provider.creates for provider in case.providers.values()) == 1


def test_scope_mismatch_retains_the_returned_id_for_cleanup(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.providers["spaces"].wrong_scope = True
    with pytest.raises(LifecycleError, match="scope or status"):
        case.issue()
    assert "created:archive" in case.lifecycle.records()
    assert case.state.credential(case.manifest.intents[0]) is not None
    assert "close-provisioning-failed" in case.lifecycle.records()


@pytest.mark.parametrize("boundary", range(1, len(ROLES) + 1))
def test_cancellation_during_each_inflight_create_keeps_writer_unresolved_until_return(
    tmp_path: Path, boundary: int
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    entered = 0

    def suspended_create() -> None:
        nonlocal entered
        entered += 1
        if entered == boundary:
            case.lifecycle.request_close("cancel")
            # The current call can still create when it resumes. Provider absence
            # while suspended cannot close this lease, even after earlier deletion.
            assert all(
                row.status == "unresolved"
                for row in case.lifecycle.reconcile(case.cleanup_providers)
            )
            assert "issuer-stopped" not in case.lifecycle.records()

    for provider in case.providers.values():
        provider.on_create = suspended_create
    if boundary < len(ROLES):
        with pytest.raises(LifecycleError, match="cancelled"):
            case.issue()
    else:
        case.issue()
    assert sum(provider.creates for provider in case.providers.values()) == boundary
    assert "close-cancel" in case.lifecycle.records()
    assert "issuer-stopped" in case.lifecycle.records()
    assert all(row.status == "verified" for row in case.lifecycle.reconcile(case.cleanup_providers))
    assert all(not provider.items for provider in case.providers.values())


def test_unreadable_inventory_cannot_declare_cold_lease_not_due(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    cold = LeaseLifecycle(
        case.manifest,
        case.inventory,
        LeaseState(tmp_path / "cold"),
        providers={},
        clock=lambda: NOW,
    )

    def unavailable() -> list[dict[str, object]]:
        raise LifecycleError("synthetic unavailable inventory")

    monkeypatch.setattr(case.inventory, "records", unavailable)
    assert all(row.status == "unresolved" for row in cold.reconcile(case.cleanup_providers))
    assert all(not provider.deletes for provider in case.cleanup_providers.values())


def test_duplicate_role_submission_requires_a_new_lease_not_a_new_writer(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.state.claim_issuer(writer_sha256="a" * 64)
    case.state.submitting(case.manifest.intents[0], writer_sha256="a" * 64)
    with pytest.raises(LifecycleError, match="already have been submitted"):
        case.state.submitting(case.manifest.intents[0], writer_sha256="a" * 64)


def test_cleanup_reads_back_every_removal_and_checks_retained_authentication(
    tmp_path: Path,
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    case.lifecycle.request_close("finish")
    results = case.lifecycle.reconcile(case.cleanup_providers)
    assert all(
        result.status == "verified" and result.negative_authentication == "denied"
        for result in results
    )
    assert sum(len(provider.deletes) for provider in case.cleanup_providers.values()) == len(ROLES)
    assert not any(provider.items for provider in case.cleanup_providers.values())
    assert case.lifecycle.reconcile(case.cleanup_providers) == results
    assert sum(len(provider.deletes) for provider in case.cleanup_providers.values()) == len(ROLES)


@pytest.mark.parametrize("wrong_scope", [False, True])
def test_lost_reply_only_revokes_a_strictly_owned_match(tmp_path: Path, wrong_scope: bool) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.providers["spaces"].lose_response = True
    case.providers["spaces"].wrong_scope = wrong_scope
    with pytest.raises(LifecycleError):
        case.issue()
    results = case.lifecycle.reconcile(case.cleanup_providers)
    assert results[0].status == ("unresolved" if wrong_scope else "verified")
    assert case.cleanup_providers["spaces"].deletes == (
        [] if wrong_scope else ["synthetic-archive"]
    )
    if not wrong_scope:
        assert results[0].negative_authentication == "unavailable"
        assert "created:archive" in case.lifecycle.records()


@pytest.mark.parametrize(
    "failure", ["keep_deleted", "fail_delete", "fail_read", "still_authenticates"]
)
def test_failed_removal_or_negative_probe_survives_retry(tmp_path: Path, failure: str) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    case.lifecycle.request_close("cancel")
    setattr(case.cleanup_providers["spaces"], failure, True)
    assert any(
        result.status == "unresolved" for result in case.lifecycle.reconcile(case.cleanup_providers)
    )
    setattr(case.cleanup_providers["spaces"], failure, False)
    assert all(
        result.status == "verified" for result in case.lifecycle.reconcile(case.cleanup_providers)
    )


def test_independent_cleanup_cannot_erase_a_failed_negative_probe(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    case.lifecycle.request_close("cancel")
    case.cleanup_providers["spaces"].still_authenticates = True
    assert any(
        result.status == "unresolved" for result in case.lifecycle.reconcile(case.cleanup_providers)
    )
    independent = LeaseLifecycle(
        case.manifest,
        case.inventory,
        LeaseState(tmp_path / "independent-host"),
        providers=case.cleanup_providers,
        clock=lambda: NOW,
    )
    assert any(
        result.status == "unresolved" for result in independent.reconcile(case.cleanup_providers)
    )
    case.cleanup_providers["spaces"].still_authenticates = False
    assert all(
        result.status == "verified" for result in case.lifecycle.reconcile(case.cleanup_providers)
    )
    assert all(
        result.status == "verified" for result in independent.reconcile(case.cleanup_providers)
    )


def test_unfenced_writer_blocks_closure_even_after_owned_key_removal(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    intent = case.manifest.intents[0]
    case.state.claim_issuer(writer_sha256="a" * 64)
    case.state.submitting(intent, writer_sha256="a" * 64)
    case.providers["spaces"].create(
        intent, record=lambda key, secret: case.state.remember(intent, key, secret)
    )
    case.lifecycle.request_close("cancel")
    assert all(
        result.status == "unresolved" for result in case.lifecycle.reconcile(case.cleanup_providers)
    )
    assert case.cleanup_providers["spaces"].deletes == ["synthetic-archive"]
    assert "issuer-stopped" not in case.lifecycle.records()


def test_publication_failure_does_not_suppress_provider_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()

    def unavailable(_record: dict[str, object]) -> None:
        raise LifecycleError("synthetic Connect outage")

    with monkeypatch.context() as scoped:
        scoped.setattr(case.inventory, "publish", unavailable)
        with pytest.raises(LifecycleError, match="Connect outage"):
            case.lifecycle.request_close("cancel")
        assert all(
            result.status == "unresolved"
            for result in case.lifecycle.reconcile(case.cleanup_providers)
        )
        assert not any(provider.items for provider in case.cleanup_providers.values())
    assert all(
        result.status == "verified" for result in case.lifecycle.reconcile(case.cleanup_providers)
    )


def test_wrong_cleanup_generation_cannot_treat_empty_inventory_as_absence(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    case.lifecycle.request_close("cancel")
    wrong = dict(case.cleanup_providers)
    wrong["spaces"] = LeaseProviderDouble("spaces", "0" * 64)
    assert any(result.status == "unresolved" for result in case.lifecycle.reconcile(wrong))
    assert wrong["spaces"].deletes == []


@pytest.mark.parametrize("fault", ["scope", "expiry", "principal", "empty", "none"])
def test_handover_requires_positive_exact_policy_and_principal_readback(
    tmp_path: Path, fault: str
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.issue()
    replacement = dataclasses.replace(
        case.manifest.cleanup,
        generation_id=str(uuid.uuid7()),
        fingerprints={kind: digest(["replacement", kind]) for kind in PROVIDERS},
    )
    providers = {
        kind: LeaseProviderDouble(kind, replacement.fingerprints[kind]) for kind in PROVIDERS
    }
    for kind, provider in providers.items():
        provider.items = deepcopy(case.cleanup_providers[kind].items)
    if fault == "principal":
        replacement = dataclasses.replace(
            replacement, principals={**replacement.principals, "spaces": "synthetic-other-team"}
        )
    elif fault == "empty":
        providers["spaces"].items.clear()
    elif fault == "scope":
        providers["spaces"].items["synthetic-archive"]["scope"] = {"wrong": True}
    elif fault == "expiry":
        providers["cloudflare-account"].items["synthetic-audit"]["expires_at"] = stamp(
            NOW + timedelta(days=8)
        )
    if fault != "none":
        with pytest.raises(LifecycleError):
            case.lifecycle.handover(replacement, providers, case.cleanup_providers)
        affected = "audit" if fault == "expiry" else "archive"
        assert not any(slot.startswith("handover:" + affected) for slot in case.lifecycle.records())
        return
    case.lifecycle.handover(replacement, providers, case.cleanup_providers)
    case.lifecycle.request_close("finish")
    results = case.lifecycle.reconcile({}, generations={replacement.generation_id: providers})
    assert all(result.status == "verified" for result in results)
    assert not any(provider.deletes for provider in case.cleanup_providers.values())
    assert sum(len(provider.deletes) for provider in providers.values()) == len(ROLES)


def test_lost_response_obligation_does_not_transfer_to_empty_replacement(tmp_path: Path) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    case.providers["spaces"].lose_response = True
    with pytest.raises(LifecycleError):
        case.issue()
    replacement = dataclasses.replace(case.manifest.cleanup, generation_id=str(uuid.uuid7()))
    with pytest.raises(LifecycleError, match="unknown credential"):
        case.lifecycle.handover(replacement, case.cleanup_providers, case.cleanup_providers)
    assert not any(slot.startswith("handover:") for slot in case.lifecycle.records())
