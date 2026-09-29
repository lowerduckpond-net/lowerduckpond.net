"""Diagnostic-only public issuer continuation, loaded solely into an owned fixture.

The original public-probe records are retained. Repeated diagnostic starts are
logged by the controller and never represented as another cold qualification.
"""

from __future__ import annotations

from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_activation import finish_public_ingress
from lowerduckpond_static_host_agent.host_restore_gate import (
    INGRESS,
    close_gate,
    ingress_record,
    open_gate,
    restore_admission,
)
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore
from lowerduckpond_static_host_agent.host_restore_process import require_command

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe
from scripts.m3_11_debug_dns_probe import retire


def diagnostic_retire_dns(context_sha256: str, expected: object) -> dict[str, object]:
    return retire(context_sha256, expected)


def diagnostic_stop_failed(context_sha256: str) -> dict[str, object]:
    probe._stop_failed(context_sha256)
    # The controller retains each diagnostic failure. Never rewrite the original
    # qualification's failed.json or require another exclusively-created record.
    return {"stopped": True, "qualification_authority": "none"}


def diagnostic_prepare(value: dict[str, object]) -> dict[str, object]:
    probe._fixture()
    if not (policy.INPUTS / "original.json").exists():
        return {"cold": True, "original": probe.install(value)}
    marker = probe._document("original")
    if any(
        marker[key] != value[key] for key in ("context_sha256", "binary", "binary_sha256", "nonce")
    ):
        raise ValueError("diagnostic public inputs differ from the retained attempt")
    with RestoreStore.locked(policy.RECOVERY) as store:
        if probe._journal(store) != marker["journal_sha256"]:
            raise ValueError("diagnostic public attempt lost its original completed restore")
        journal = store.read()
        if journal is None:
            raise ValueError("diagnostic completed restore disappeared")
        close_gate(store, journal.restore_id)
        services.close_public_ingress()
        services.quiesce_host()
    probe._systemctl("stop", probe.COORDINATOR, policy.UNIT, probe.DNS_UNIT)
    probe._systemctl("disable", "caddy.service", probe.DNS_UNIT)
    # The diagnostic attempt may follow a completed native reactivation.

    require_command(
        ("/usr/sbin/nft", "destroy", "table", "ip", "restore_fixture_dns"),
        failure="diagnostic_controlled_dns_removal_failed",
        timeout=10,
    )
    probe._guard(str(value["context_sha256"]))
    probe._closed()
    return {"cold": False}


def diagnostic_start(context_sha256: str) -> dict[str, object]:
    probe._guard(context_sha256)
    probe._closed()
    probe._systemctl("start", policy.UNIT)
    return {"started": True}


def diagnostic_interrupt(context_sha256: str) -> dict[str, object]:
    probe._guard(context_sha256)
    probe._closed()
    probe._systemctl("stop", policy.UNIT)
    inventory = probe._inventory()
    if not any(name.startswith("acme/") and name.endswith(".key") for name in inventory):
        raise ValueError("diagnostic interruption did not retain an actual ACME account")
    return {"storage": inventory}


def diagnostic_open(context_sha256: str, expected: dict[str, object]) -> dict[str, object]:
    marker = probe._guard(context_sha256)
    probe._closed()
    with RestoreStore.locked(policy.RECOVERY) as store:
        if probe._tls(marker) != expected or probe._journal(store) != marker["journal_sha256"]:
            raise ValueError("diagnostic public TLS or restore identity changed")
        store.immutable(INGRESS[0], ingress_record(store))
        open_gate(store)
        finish_public_ingress(store)
    if not restore_admission():
        raise ValueError("diagnostic public ingress did not restore admission")
    return {"opened": True}


def diagnostic_finish(
    context_sha256: str, expected: dict[str, object], *, audit_rotation: bool
) -> dict[str, object]:
    marker = probe._guard(context_sha256)
    with RestoreStore.locked(policy.RECOVERY) as store:
        if probe._tls(marker) != expected or probe._journal(store) != marker["journal_sha256"]:
            raise ValueError("diagnostic public TLS or restore identity changed")
    if not restore_admission():
        raise ValueError("diagnostic native reactivation requires verified public ingress")
    probe._systemctl("stop", policy.UNIT)
    probe._systemctl("enable", "--now", probe.DNS_UNIT)
    services.start_caddy()
    with RestoreStore.locked(policy.RECOVERY) as store:
        journal = store.read()
        if journal is None:
            raise ValueError("diagnostic completed restore disappeared")
        if probe._journal(store) != marker["journal_sha256"]:
            raise ValueError("diagnostic restore changed while reactivating native Caddy")
        services.SCHEDULES_READY.parent.mkdir(mode=0o700, exist_ok=True)
        with DurableDirectory.open(
            services.SCHEDULES_READY.parent, expected_owner=0, expected_directory_mode=0o700
        ) as directory:
            directory.replace((services.SCHEDULES_READY.name,), journal.to_bytes(), mode=0o600)
        services.restore_schedules(audit_rotation=audit_rotation)
    return {"native_restored": True}
