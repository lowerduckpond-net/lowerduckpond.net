"""Protected independent Connect confirmation and credential-only cleanup.

A versioned cleanup-only bundle arrives on stdin. The action starts its own
Connect cache and never uses the issuance host's endpoint or private volumes.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import cleanup
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import authenticate
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.connect_host import independent_server
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.inventory import ConnectInventory
from scripts.m3_11_unattended.model import LifecycleError, stamp, strings
from scripts.m3_11_unattended.state import replace_private
from scripts.production_qualification_inputs import current_candidate, revision

FORMAT = "lowerduckpond-m3-11-independent-lease-bundle-v1"
RECEIPT_FORMAT = "lowerduckpond-m3-11-independent-lease-receipt-v1"
REPOSITORY = "lowerduckpond-net/lowerduckpond.net"
WORKFLOW = "m3-11-credential-cleanup.yml"
# This is the existing bounded Connect startup allowance, not issuance policy.
SYNC_SECONDS = 120
POLL_SECONDS = 5
MAX_INPUT = 128 * 1024
INDEPENDENT_ORIGIN = "https://independent.invalid"


def bootstrap(value: object, *, helper: str) -> tuple[LeaseConfiguration, dict[str, object]]:
    selected = fields(value, {"format", "configuration", "server_credentials"})
    config = LeaseConfiguration.parse(selected["configuration"])
    credentials = selected["server_credentials"]
    if (
        selected["format"] != FORMAT
        or config.mode != "cleanup-only"
        or config.helper_revision != revision(helper)
        or not isinstance(credentials, dict)
        or not credentials
    ):
        raise LifecycleError("independent cleanup bundle differs from its approved helper")
    for roles in config.generations.values():
        reader, access = reader_access(roles["cleanup"].reader_settings, allow_expired=True)
        if access.server_id != config.independent_server_id or reader["url"] != INDEPENDENT_ORIGIN:
            raise LifecycleError("independent cleanup must use only its separate Connect identity")
    return config, credentials


def execute(
    raw: object,
    *,
    directory: Path,
    helper: str,
    progress: Callable[[str], None] = lambda _stage: None,
) -> dict[str, object]:
    selected = fields(raw, {"bootstrap", "operation"})
    if selected["operation"] not in {"confirm", "cleanup"}:
        raise LifecycleError("independent cleanup operation is unsupported")
    config, credentials = bootstrap(selected["bootstrap"], helper=helper)
    active = config.generations[config.active_generation]["cleanup"]
    reader, access = reader_access(active.reader_settings)
    vaults = strings(reader["vaults"])
    progress("independent-connect")
    with independent_server(Docker(), credentials) as endpoint:
        client = Connect(endpoint, access.token, local_cleanup=True)
        until = time.monotonic() + SYNC_SECONDS
        replace_private(
            directory / "authentication.json", {**access.receipt(), "status": "pending"}
        )
        while True:
            try:
                authentication = authenticate(
                    client, access, forbidden=set(vaults.values()) - access.grants.keys()
                )
                break
            except LifecycleError:
                if time.monotonic() >= until:
                    raise
                time.sleep(POLL_SECONDS)
        replace_private(
            directory / "authentication.json",
            {**authentication, "status": "verified", "observed_at": stamp(datetime.now(UTC))},
        )
        inventory = ConnectInventory(client, config.journal_vault, spool=directory / "pending")
        confirmation = None
        if selected["operation"] == "confirm":
            run_id, attempt = (
                os.environ.get("GITHUB_RUN_ID", ""),
                os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            )
            if (
                not run_id.isdecimal()
                or not attempt.isdecimal()
                or min(int(run_id), int(attempt)) < 1
            ):
                raise LifecycleError("independent execution identity is unavailable")
            confirmation = {
                "helper_revision": helper,
                "independent_server_id": access.server_id,
                "cleanup_access_expires_at": stamp(access.expires_at),
                "observed_at": stamp(datetime.now(UTC)),
                "github_run_id": int(run_id),
                "github_run_attempt": int(attempt),
            }
        progress("credential-cleanup")
        receipt = cleanup.sweep_leases(
            config,
            inventory,
            root=directory / "leases",
            actor="github",
            confirmation=confirmation,
            connect_client=client,
        )
        # Teardown may fail after cleanup; retain the actual cleanup result first.
        replace_private(directory / "cleanup.json", receipt)
    return {**receipt, "format": RECEIPT_FORMAT}


def main() -> int:
    os.umask(0o077)
    directory = Path(os.environ["RUNNER_TEMP"]) / "m3-11-connect"
    directory.mkdir(mode=0o700)
    phase = "protected-execution"

    def progress(value: str) -> None:
        nonlocal phase
        phase = value
        replace_private(
            directory / "receipt.json",
            {"format": RECEIPT_FORMAT, "status": "unresolved", "phase": phase},
        )

    try:
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main"
        ):
            raise LifecycleError("independent cleanup requires the protected main workflow")
        helper = revision(os.environ["M3_11_HELPER_REVISION"])
        current_candidate(Path(__file__).resolve().parents[2], helper)

        def interrupted(_signum: int, _frame: object) -> None:
            raise LifecycleError("independent cleanup was interrupted")

        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupted)
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise LifecycleError("independent cleanup input exceeds its bound")
        receipt = execute(json.loads(raw), directory=directory, helper=helper, progress=progress)
    except Exception:
        # Never export native errors, bootstrap fields, paths or provider output.
        receipt = {"format": RECEIPT_FORMAT, "status": "unresolved", "phase": phase}
    replace_private(directory / "receipt.json", receipt)
    return 0 if receipt["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
