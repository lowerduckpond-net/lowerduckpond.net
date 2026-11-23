"""Leased physical rollback of an enrolled, pre-tenant successor."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path

from lowerduckpond_static_contracts import decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.audit import has_tenant_audit_history
from lowerduckpond_static_host_agent.caddy_admin import CaddyAdminError, verify_running_caddy
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_ROUTE_METADATA_NAME,
    MAX_CADDY_ROUTE_METADATA_BYTES,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore
from lowerduckpond_static_host_agent.droplet_enrollment import PUBLICATION_VIEW
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.platform_launch import INTENT, LAUNCH
from lowerduckpond_static_host_agent.repository import StateRepository
from scripts.m3_12_contracts import MAX_RECORD_BYTES, Document, digest, encode, require

FENCE = ("publication-fence.json",)
PREDECESSOR = ("preceding-generation.json",)
GATE_FORMAT = "lowerduckpond-static-publication-gate-v1"


def _read(directory: DurableDirectory, key: tuple[str, ...], owner: int) -> bytes | None:
    try:
        return directory.read_regular(
            key, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
        )
    except FileNotFoundError:
        return None


def _record(directory: DurableDirectory, key: tuple[str, ...], owner: int) -> Document | None:
    raw = _read(directory, key, owner)
    return None if raw is None else decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)


def _store(directory: DurableDirectory, key: tuple[str, ...], doc: Document, owner: int) -> None:
    raw = encode(doc)
    previous = _read(directory, key, owner)
    if previous is None:
        directory.create_immutable(key, raw)
    else:
        require(previous == raw, "rollback-original-changed")


def _generation(generation: PinnedCaddyGeneration, *, preceding: bool = False) -> Document:
    fd = generation.duplicate_payload_descriptor(CADDY_ROUTE_METADATA_NAME)
    try:
        metadata = decode_json_object(
            os.pread(fd, MAX_CADDY_ROUTE_METADATA_BYTES + 1, 0),
            maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES,
        )
    finally:
        os.close(fd)
    route = metadata["routeState"]
    require(
        type(route) is dict
        and route.get("tenantRouteCount") == 0
        and (not preceding or route.get("generationClass") == "platform-only"),
        "rollback-generation-not-platform-only",
    )
    return {
        "generation": generation.manifest.generation_id,
        "manifestSha256": sha256(generation.manifest.to_bytes()).hexdigest(),
    }


class PhysicalRollback:
    """Use the actual Caddy selector and ordered state locks under an action lease."""

    def __init__(  # noqa: PLR0913 - actual paths, lease and native effect are explicit
        self,
        state: Path,
        authority: Path,
        configuration: Path,
        runtime: CaddyRuntime,
        *,
        require_lease: Callable[[], None],
        restart: Callable[[], None],
        startup: CaddyStartupStore | None = None,
        owner: int = 0,
    ) -> None:
        self.state = state
        self.authority = authority
        self.configuration = configuration
        self.runtime = runtime
        self.require_lease = require_lease
        self.restart = restart
        self.startup = startup
        self.owner = owner

    @contextmanager
    def locked(self) -> Iterator[tuple[DurableDirectory, DurableDirectory]]:
        self.require_lease()
        with (
            DurableDirectory.open(
                self.authority, expected_owner=self.owner, expected_directory_mode=0o700
            ) as records,
            DurableDirectory.open(
                self.state, expected_owner=self.owner, expected_directory_mode=0o700
            ) as state,
            StateRepository(self.state, expected_owner=self.owner) as repository,
            repository.publication_transaction() as transaction,
            self.runtime.using_held_publication_lock(repository),
        ):
            require(
                self.startup is None or self.startup.inventory_is_empty(),
                "rollback-caddy-startup-is-pending",
            )
            inventory = transaction.measure_inventory()
            require(
                not inventory.tenant_count
                and not inventory.authorization_record_count
                and not transaction.measure_intent_records().records
                and not has_tenant_audit_history(
                    state,
                    expected_owner=self.owner,
                    expected_directory_mode=0o700,
                    expected_record_mode=0o600,
                ),
                "rollback-history-or-work",
            )
            yield records, state

    def gate(self, *, value: bool | None = None) -> bool:
        with DurableDirectory.open(
            self.configuration.parent, expected_owner=self.owner, expected_directory_mode=0o700
        ) as config:
            key = (self.configuration.name,)
            raw = config.read_regular(
                key, expected_owner=self.owner, expected_mode=0o400, maximum_bytes=4096
            )
            current = decode_json_object(raw)
            enabled = current.get("static_publication_enabled")
            require(
                type(enabled) is bool
                and current == {"format": GATE_FORMAT, "static_publication_enabled": enabled},
                "rollback-publication-policy-changed",
            )
            if not isinstance(enabled, bool):
                raise ValueError("rollback-publication-policy-changed")
            if value is not None and value is not enabled:
                config.replace(
                    key,
                    encode({"format": GATE_FORMAT, "static_publication_enabled": value}),
                    mode=0o400,
                )
            return enabled

    def pin_predecessor(self) -> Document:
        """Retain the actual platform-only target before successor staging."""
        with self.locked() as (records, _):
            existing = _record(records, PREDECESSOR, self.owner)
            identity = self.runtime.read_active() if existing is None else existing["generation"]
            with self.runtime.open_verified_generation(identity) as active:
                original = _generation(active, preceding=True)
            _store(records, PREDECESSOR, original, self.owner)
            return original

    def _retained(self, records: DurableDirectory, state: DurableDirectory) -> Document:
        launch = _read(state, LAUNCH, self.owner)
        intent = _read(records, INTENT, self.owner)
        require(launch is None or intent is not None, "rollback-launch-intent-missing")
        return {
            "retainedLaunchSha256": None if launch is None else sha256(launch).hexdigest(),
            "retainedIntentSha256": None if intent is None else sha256(intent).hexdigest(),
        }

    def _plan(
        self,
        records: DurableDirectory,
        state: DurableDirectory,
        decision: Document,
        authorize: Callable[[], None],
    ) -> Document:
        key = ("physical-" + digest(decision) + ".json",)
        retained = self._retained(records, state)
        predecessor = _record(records, PREDECESSOR, self.owner)
        require(predecessor is not None, "rollback-original-generation-missing")
        if predecessor is None:
            raise ValueError("rollback-original-generation-missing")
        require(
            decision["precedingGenerationSha256"] == predecessor["manifestSha256"]
            and all(decision[name] == value for name, value in retained.items()),
            "rollback-physical-binding-changed",
        )
        with self.runtime.open_verified_generation(predecessor["generation"]) as preceding:
            require(
                _generation(preceding, preceding=True) == predecessor, "rollback-original-changed"
            )

        plan = _record(records, key, self.owner)
        if plan is not None:
            authorize()
            return plan
        active = self.runtime.read_active()
        with self.runtime.open_verified_generation(active) as generation:
            source = _generation(generation)
        fence = _record(records, FENCE, self.owner)
        if decision["action"] == "restore-platform-only":
            if fence is not None:
                require(fence["decisionSha256"] == digest(decision), "rollback-already-active")
                authorize()
                _store(records, key, fence, self.owner)
                return fence
            desired, enabled = predecessor, False
        elif decision["action"] == "reactivate-same-policy":
            require(
                fence is not None
                and source == predecessor
                and not self.gate()
                and all(fence[name] == value for name, value in retained.items()),
                "rollback-not-reconciled",
            )
            if fence is None:
                raise ValueError("rollback-not-reconciled")
            dark_effect = _record(
                records, ("effect-" + fence["decisionSha256"] + ".json",), self.owner
            )
            require(dark_effect == fence, "rollback-not-reconciled")
            desired = fence["source"]
            enabled = fence["sourceEnabled"] and retained["retainedLaunchSha256"] is not None
        else:
            raise ValueError("rollback-operation-unknown")
        plan = {
            "format": "lowerduckpond-m3-12-physical-rollback-v1",
            "decisionSha256": digest(decision),
            "source": source,
            "desired": desired,
            "sourceEnabled": self.gate(),
            "desiredEnabled": enabled,
            **retained,
        }
        authorize()
        if decision["action"] == "restore-platform-only":
            # Close before publishing any plan whose physical continuation may
            # be lost. A fence without a plan has the same original identity.
            _store(records, FENCE, plan, self.owner)
        _store(records, key, plan, self.owner)
        return plan

    def _verified_generation(self, reference: Document) -> PinnedCaddyGeneration:
        generation = self.runtime.open_verified_generation(validate_uuid7(reference["generation"]))
        try:
            require(_generation(generation) == reference, "rollback-generation-changed")
        except BaseException:
            generation.close()
            raise
        return generation

    def reconcile(
        self,
        decision: Document,
        *,
        authorize: Callable[[], None] = lambda: None,
        after_selection: Callable[[], None] | None = None,
    ) -> Document:
        """Finish the exact approved effect, including after selector publication."""
        with self.locked() as (records, state):
            plan = self._plan(records, state, decision, authorize)
            require(
                self._retained(records, state)
                == {name: plan[name] for name in ("retainedLaunchSha256", "retainedIntentSha256")},
                "rollback-original-launch-changed",
            )
            effect_key = ("effect-" + plan["decisionSha256"] + ".json",)
            effect = _record(records, effect_key, self.owner)
            if effect is not None:
                require(effect == plan, "rollback-effect-changed")
                self._finish_gate(records, decision, plan)
                return effect
            if decision["action"] == "restore-platform-only":
                _store(records, FENCE, plan, self.owner)
            else:
                require(_record(records, FENCE, self.owner) is not None, "rollback-fence-missing")
            self.gate(value=False)
            active = self.runtime.read_active()
            require(
                active in {plan["source"]["generation"], plan["desired"]["generation"]},
                "rollback-selected-unrelated-generation",
            )
            with self._verified_generation(plan["desired"]) as generation:
                destination = generation.manifest.generation_id
                if active == destination:
                    self.runtime.sync_active(destination)
                else:
                    self.runtime.select_active(destination)
                try:
                    verify_running_caddy(generation)
                except CaddyAdminError:
                    restart = True
                else:
                    restart = False
        if after_selection is not None:
            after_selection()
        if restart:
            self.require_lease()
            self.restart()
        with self.locked() as (records, state):
            require(
                self._retained(records, state)
                == {name: plan[name] for name in ("retainedLaunchSha256", "retainedIntentSha256")}
                and self.runtime.read_active() == plan["desired"]["generation"],
                "rollback-selected-unrelated-generation",
            )
            with self._verified_generation(plan["desired"]) as generation:
                verify_running_caddy(generation)
            _store(records, effect_key, plan, self.owner)
            self._finish_gate(records, decision, plan)
            return plan

    def _finish_gate(self, records: DurableDirectory, decision: Document, plan: Document) -> None:
        require(
            self.runtime.read_active() == plan["desired"]["generation"],
            "rollback-selected-unrelated-generation",
        )
        with self._verified_generation(plan["desired"]) as generation:
            verify_running_caddy(generation)
        if decision["action"] == "reactivate-same-policy":
            self.gate(value=plan["desiredEnabled"])
            records.remove(FENCE, missing_ok=True)
        else:
            require(
                not self.gate() and _record(records, FENCE, self.owner) == plan,
                "rollback-fence-missing",
            )


SUCCESSOR_AUTHORITY = Path("/var/lib/lowerduckpond/convergence/m3-12")


def require_unfenced_publication(authority: Path = SUCCESSOR_AUTHORITY) -> None:
    """Fence both configuration checks and admitted requests racing a rollback."""
    if not os.path.lexists(authority):
        return
    require(
        not os.path.lexists(authority.joinpath(*FENCE))
        and not os.path.lexists(authority.joinpath(PUBLICATION_VIEW, *FENCE)),
        "successor-publication-fenced",
    )
    if os.path.lexists(authority / "transaction.json"):
        from scripts.m3_12_successor_journal import SuccessorJournal  # noqa: PLC0415

        with DurableDirectory.open(
            authority, expected_owner=0, expected_directory_mode=0o700
        ) as directory:
            journal = SuccessorJournal(directory, 0)
            require(len(journal.snapshot().rollbacks) % 2 == 0, "successor-publication-fenced")
