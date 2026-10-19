"""Shared credential semantics with request-scoped, read-only admission transport."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import cast

from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.check_m3_10_provider import PolicyClient
from scripts.m3_10_policy_client import make_policy_client
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_api import Response as ConnectResponse
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.inventory import ConnectInventoryReader
from scripts.m3_11_unattended.lifecycle import validate_reused_credentials
from scripts.m3_11_unattended.model import Credential, Intent, LeaseManifest, LifecycleError
from scripts.m3_11_unattended.spaces import Spaces
from scripts.m3_11_unattended.state import LeaseState

CONTROL_SECONDS = 30


@contextmanager
def read_only_requests(guard: Callable[[], None]) -> Iterator[dict[str, int]]:
    """Single native helper process; never alter another execution's transport."""
    from scripts.m3_11_unattended.storage_admission import require_remaining  # noqa: PLC0415

    original_api, original_connect, original_probe = Api._request, Connect.request, Spaces._probe
    counts = {"control_read_count": 0, "credential_probe_read_count": 0}

    def before(seconds: int, category: str) -> None:
        guard()
        require_remaining(seconds)
        counts[category] += 1

    def api(self: Api, method: str, path: str, body: dict[str, object] | None) -> Response:
        if method != "GET" or body is not None:
            raise LifecycleError("credential readiness attempted a provider mutation")
        before(CONTROL_SECONDS, "control_read_count")
        return original_api(self, method, path, body)

    def connect(
        self: Connect, method: str, path: str, body: dict[str, object] | None = None
    ) -> ConnectResponse:
        if method != "GET" or body is not None:
            raise LifecycleError("credential readiness attempted a journal mutation")
        before(CONTROL_SECONDS, "control_read_count")
        return original_connect(self, method, path, body)

    def probe(intent: Intent, credential: Credential) -> None:
        bucket = (
            intent.targets.backup_bucket
            if intent.role == "backup"
            else intent.targets.archive_bucket
        )
        client = make_policy_client(
            ArchiveConfiguration(
                intent.targets.region, bucket, credential.identifier, credential.secret
            )
        )

        def read(_request: object = None, **_kwargs: object) -> None:
            before(
                40, "credential_probe_read_count"
            )  # Existing no-retry policy: connect 10 + read 30.

        client.meta.events.register("request-created.s3", read)  # type: ignore[attr-defined]
        cast(PolicyClient, client).list_objects_v2(Bucket=bucket, MaxKeys=1)

    Api._request = api  # type: ignore[method-assign]
    Connect.request = connect  # type: ignore[method-assign]
    Spaces._probe = staticmethod(probe)  # type: ignore[method-assign]
    try:
        yield counts
    finally:
        Api._request = original_api  # type: ignore[method-assign]
        Connect.request = original_connect  # type: ignore[method-assign]
        Spaces._probe = staticmethod(original_probe)  # type: ignore[method-assign]


def validate_all_roles(
    config: LeaseConfiguration,
    manifest: LeaseManifest,
    state: LeaseState,
    *,
    clock: Callable[[], datetime],
    guard: Callable[[], None],
) -> Callable[[], None]:
    bootstrap = config.generations[config.active_generation]["cleanup"]
    bootstrap.generation.require_same_principal(manifest.cleanup)
    reader = bootstrap.reader()
    inventory = ConnectInventoryReader(reader, config.journal_vault)

    def observed() -> dict[str, dict[str, object]]:
        guard()
        records = {
            str(row["slot"]): row
            for row in inventory.records()
            if row["lease_id"] == manifest.lease_id
        }
        if (
            any(row["manifest_sha256"] != manifest.sha256 for row in records.values())
            or records.get("manifest", {}).get("payload") != manifest.document()
            or records.get("issuer-stopped", {}).get("payload") != state.issuer_stop()
            or any(slot.startswith("close-") or slot == "closed" for slot in records)
        ):
            raise LifecycleError("credential readiness journal is closing or differs")
        return records

    original = observed()
    providers = bootstrap.providers(targets=config.targets, now=clock(), reader=reader)
    validate_reused_credentials(manifest, state, providers, original, clock=clock, guard=guard)

    def final() -> None:
        current = observed()
        if any(
            current.get("created:" + intent.role) != original.get("created:" + intent.role)
            for intent in manifest.intents
        ):
            raise LifecycleError("credential readiness ownership facts changed")
        guard()

    return final
