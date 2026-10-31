"""The shared cold public-CA transition sequence, without qualification authority.

Native qualification and the separate isolated diagnostic supply their own
validated identities, input capture and DNS witness. This module cannot allocate
fixtures, choose a resolver, authorize credentials or write a success report.
"""

from __future__ import annotations

from typing import Protocol

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_dns_witness import DnsWitness


class Recovery(Protocol):
    installed: bool
    witness: DnsWitness

    @property
    def audit_rotation(self) -> bool: ...

    def call(self, action: str, **arguments: object) -> dict[str, object]: ...

    def peer(self, *, opened: bool) -> None: ...

    def gate_closed(self) -> None: ...

    def reboot(self) -> None: ...

    def drain_issuance(self, *, diagnostic: bool = False) -> dict[str, object]: ...

    def _remaining(self) -> int: ...

    def _wait(self) -> None: ...

    def _identity(self) -> None: ...


def exercise(recovery: Recovery, value: dict[str, object]) -> dict[str, object]:
    """Observe actual publication, interruption, reboot and native TLS readiness."""
    original = recovery.call("install", value=value)
    recovery.installed = True
    recovery.call("start")
    recovery.gate_closed()
    recovery.peer(opened=False)
    observations = []
    while True:
        recovery._remaining()
        observation = recovery.witness.sample("activity")
        observations.append(observation.sha256)
        if observation.record_count and recovery.witness.both_zones_observed:
            interruption_cleanup = recovery.drain_issuance()
            interrupted = recovery.call("interrupt")
            break
        if recovery.call("ready")["ready"]:
            raise ValueError("public issuance finished without an observed interruption")
        recovery._wait()
    recovery.gate_closed()
    recovery.reboot()
    reboot = recovery.call("rebooted")
    recovery.gate_closed()
    recovery.peer(opened=False)
    recovery.call("start", resume=True)
    while True:
        recovery._remaining()
        observations.append(recovery.witness.sample("activity").sha256)
        result = recovery.call("ready")
        if result["ready"]:
            tls = evidence.fields(result["tls"], {"issuer", "certificates"})
            break
        recovery._wait()
    recovery.witness.require_both_zones_observed()
    cleanup = recovery.witness.require_absent("cleanup")
    recovery.peer(opened=False)
    opened = recovery.call("open_verified", expected=tls)
    recovery.peer(opened=True)
    restored = recovery.call("restore_native", audit_rotation=recovery.audit_rotation)
    recovery._identity()
    return {
        "original": original,
        "interrupted": interrupted,
        "interruption_cleanup": interruption_cleanup,
        "rebooted": reboot,
        "tls": tls,
        "opened": opened,
        "restored": restored,
        "dns_activity_sha256": observations,
        "dns_cleanup_sha256": cleanup.sha256,
    }
