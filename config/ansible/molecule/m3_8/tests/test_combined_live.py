"""The fixed secure-workstation node executes all six live assertion phases."""

from pathlib import Path

import combined_accounting
import combined_reconstruction
import public_ca_recovery
from testinfra.host import Host

from scripts.m3_11_combined_live import Attempt


def test_live_combined_recovery(host: Host, tmp_path: Path, m3_11_attempt: Attempt) -> None:
    # This fixture is provided only by the fixed live controller. Collection by
    # an arbitrary pytest invocation cannot silently select MinIO or omit phases.
    attempt = m3_11_attempt
    fixture, recovery = combined_reconstruction.run(
        host,
        tmp_path,
        live_storage=attempt.storage,
        recorder=attempt.recorder,
        existing_namespace=True,
    )
    public, public_ca = public_ca_recovery.run(
        fixture, attempt.storage, attempt.directory, attempt.recorder
    )
    accounting = combined_accounting.run(public, attempt.storage, attempt.recorder, recovery)
    attempt.record(public.witness, recovery, public_ca, accounting)
