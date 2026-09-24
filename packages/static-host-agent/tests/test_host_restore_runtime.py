from __future__ import annotations

import os
import ssl
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartMode,
    CaddyStartPhase,
    CaddyStartupStore,
)
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_runtime import (
    TrustedCaddy,
    prepare_restored_runtime,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - actual backup fixture
from test_backup_capture import Capture
from test_backup_inventory import TENANT
from test_host_restore_mapping import (
    ENVIRONMENT,
    NEW,
    NEW_CA,
    OLD_CA,
    setup,
)
from test_host_restore_mapping import capture as capture  # noqa: PLC0414
from test_host_restore_mapping import configuration as configuration  # noqa: PLC0414
from test_host_restore_mapping import fixture as fixture  # noqa: PLC0414
from test_host_restore_mapping import journal as journal  # noqa: PLC0414
from test_host_restore_routes import begin


@pytest.mark.parametrize(
    "boundary", ["layout", "mapping", "selection", "startup", "observation", "prepared"]
)
def test_runtime_publication_resumes_same_generation_and_mapped_observation_at_every_boundary(  # noqa: PLR0913,PLR0917
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    journal, inputs, descriptor, binary = setup(capture, configuration, journal, tmp_path)
    candidate_parent = tmp_path / "runtime-container"
    candidate_parent.mkdir(mode=0o700)
    candidate = candidate_parent / "candidate"
    files = TrustedCaddy(
        binary,
        ENVIRONMENT,
        OLD_CA,
        NEW_CA,
        tuple(ssl.DER_cert_to_PEM_cert(value).encode() for value in NEW_CA),
    )
    validations = []

    def validate(
        generation: PinnedCaddyGeneration,
        environment: dict[str, str],
        *,
        validation_uid: int,
        validation_gid: int,
    ) -> None:
        # Test adapter only for native execution. Generation publication,
        # verification, input copying, selection, startup fencing and CAS are real.
        assert validation_uid == os.geteuid() and validation_gid == os.getegid()
        assert environment["CLOUDFLARE_API_TOKEN"] == "fixture-only"  # noqa: S105 - public fixture token
        validations.append(generation.manifest.generation_id)

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.caddy_runtime._validate_generation_candidate", validate
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.caddy_generation.measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    with (
        RestoreStore.locked(capture.roots["recovery"], owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        before = repository.read(StateRecordPath.tenant_observed(TENANT)).document

        def interrupt(step: str) -> None:
            if step == boundary:
                raise RuntimeError("interrupted")

        def prepare(hook: bool = False) -> object:
            previous_umask = os.umask(0o077)
            try:
                return prepare_restored_runtime(
                    store,
                    repository,
                    candidate,
                    capture.state.root / "locks/publication.lock",
                    descriptor,
                    inputs,
                    files,
                    caddy_uid=os.geteuid(),
                    caddy_gid=os.getegid(),
                    generation_id=lambda: NEW,
                    failure_hook=interrupt if hook else lambda _step: None,
                )
            finally:
                os.umask(previous_umask)

        with pytest.raises(RuntimeError, match="interrupted"):
            prepare(True)
        proof = prepare()
        assert prepare() == proof
        assert validations and set(validations) == {NEW}
        assert (candidate / "active").read_text() == NEW + "\n"
        assert (candidate / "environment").read_bytes() == ENVIRONMENT
        assert (candidate / "origin-pull-ca-0.pem").read_bytes() == files.current_pem[0]
        after = repository.read(StateRecordPath.tenant_observed(TENANT)).document
        assert after == {**before, "runtimeGenerationId": NEW}
        with CaddyStartupStore.open(candidate / "intents", expected_owner=os.geteuid()) as startup:
            intent = startup.read()
            assert intent is not None
            assert intent.mode is CaddyStartMode.HOST_RESTORE
            assert intent.restore_id == journal.restore_id
            assert intent.phase is CaddyStartPhase.RESTART_REQUIRED
            assert intent.candidate_invocations == ()
        # The component returns proof; it cannot admit public service or skip
        # the installation, invocation and TLS phases owned by the coordinator.
        assert store.read().phase is RestorePhase.RECONCILED  # type: ignore[union-attr]
        (candidate / "environment").write_bytes(b"unexpected credential input\n")
        with pytest.raises(HostRestoreError, match="input_copy_changed"):
            prepare()
