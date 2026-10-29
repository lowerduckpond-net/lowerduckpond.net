"""Native phase orchestration after genuine local fixture preparation.

The installed fixture adapter owns allocation/convergence/reconstruction. This
controller binds that original graph, arms its separate cleanup process, and
never accepts arbitrary proof JSON or launches the full qualification journey.
No live default or shell instruction is selected by importing this module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import ModuleType
from typing import cast

from scripts.m3_11_isolation_access import HostAccess
from scripts.m3_11_isolation_github import capture
from scripts.m3_11_isolation_host import Host, readers
from scripts.m3_11_isolation_journal import Journal
from scripts.m3_11_isolation_lease import Lease
from scripts.m3_11_isolation_watch import arguments, daemon_socket, name, require_armed
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_retirement_files import record
from scripts.m3_11_unattended.model import digest


def publication(host: Host, access: HostAccess) -> Journal:
    """Publish only the exact public manifest and genuine preparation."""
    host.require()
    access.require(host.manifest)
    if read_private(host.root / "manifest.json") != host.manifest.document():
        raise ValueError("isolated private manifest binding differs")
    client = access.client("provision", host.manifest)
    journal = Journal(
        client,
        host.manifest,
        spool=host.root / "pending-controller",
        reservation=host.evidence,
        guard=host.require,
    )
    journal.put("manifest", host.manifest.document())
    journal.put("prepared", host.prepared)
    return journal


def arm(host: Host) -> str:
    """Create/start once; uncertain CREATE/START is inspected, never replayed."""
    host.require()
    entered = host.root / "watchdog-entered.json"
    # This durable entry precedes Docker CREATE. Existing entry means inspect;
    # there is deliberately no reset or automatic second CREATE path.
    if entered.exists():
        actor = host.docker.owned(name(host.manifest))
        return str(actor["Id"])
    write_private(entered, {"manifest_sha256": host.manifest.sha256})
    selected = (
        host.docker.command(*arguments(host.manifest, socket=daemon_socket(host))).decode().strip()
    )
    record(
        host.root / "watchdog-created.json",
        {"container_id": selected, "manifest_sha256": host.manifest.sha256},
    )
    host.docker.command("start", selected)
    return selected


def installed_adapter() -> ModuleType:
    import importlib  # noqa: PLC0415
    import sys  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    helper = Path(__file__).resolve().parents[1] / "config/ansible/molecule/m3_8/tests"
    if str(helper) not in sys.path:
        sys.path.insert(0, str(helper))
    module = importlib.import_module(
        "config.ansible.molecule.m3_8.tests.isolated_public_ca_recovery"
    )
    for module_name in ("restore_fixture", "restore_scenarios", "public_ca_recovery"):
        loaded = sys.modules.get(module_name)
        filename = None if loaded is None else getattr(loaded, "__file__", None)
        if filename is None or Path(filename).resolve().parent != helper:
            raise ValueError("isolated native helper import differs from the pinned source")
    return module


def execute(
    host: Host, access: HostAccess, fixture: object, *, confirmation_run: int
) -> dict[str, object]:
    """Once-only actual CF issuance and native cold recovery; watchdog owns exit."""
    adapter = installed_adapter()
    if not isinstance(fixture, adapter.Fixture):
        raise ValueError("isolated controller requires the native prepared fixture")
    host.require()
    require_armed(host)
    journal = publication(host, access)
    proof = capture(host.manifest, confirmation_run, operation="confirm")
    confirmations = [row["payload"] for row in journal.all_records() if row["kind"] == "confirmed"]
    if confirmations != [proof.receipt["github"]]:
        raise ValueError("isolated confirmation is not its authenticated exact-manifest proof")
    provider = access.provider("provision", host.manifest, client=journal.client)
    lease = Lease(host.credentials, host.manifest.intents, journal)
    # This original latch precedes any CREATE. Re-entering execute after a
    # failure is prohibited even when the provider never received a POST.
    write_private(
        host.root / "controller-entered.json",
        {"manifest_sha256": host.manifest.sha256, "confirmation": proof.provenance},
    )
    result: dict[str, object] = {"status": "failed", "qualification_authority": "none"}
    try:
        ids = lease.issue(
            provider, now=lambda: datetime.now(UTC), require_prearmed=lambda: require_armed(host)
        )
        recovery = adapter.IsolatedRecovery(
            fixture,
            host.phase,
            adapter.Setup(
                host.manifest.plan,
                host.manifest.intents,
                readers(host.credentials),
                ids,
                str(
                    cast(dict[str, dict[str, object]], host.prepared["actors"])["controller"]["id"]
                ),
                lambda: require_armed(host),
                journal.put,
            ),
        )
        functional, _ = recovery.run()
        result = {
            "status": "functional-passed-cleanup-pending",
            "functional_sha256": digest(functional),
            "qualification_authority": "none",
        }
        return result
    finally:
        # The external watchdog positively stops this controller and every
        # prepared consumer, then revokes/probes all three obligations.
        # This marker does not assert cleanup, readiness or a passing seal.
        record(host.root / "functional-terminal.json", result)
