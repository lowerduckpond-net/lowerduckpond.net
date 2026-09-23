"""Root-only phase coordinator; credentials stay in separate fixed service domains."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.audit_rotation_coordinator import RotationPaths
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_activation import (
    activate_completed_restore,
    activation_pending,
)
from lowerduckpond_static_host_agent.host_restore_audit_reconcile import (
    reconstruct_audit,
    verify_reconstructed_audit,
)
from lowerduckpond_static_host_agent.host_restore_authority import begin_restore_authority
from lowerduckpond_static_host_agent.host_restore_cold_storage import require_cold_storage
from lowerduckpond_static_host_agent.host_restore_decisions import seal_decisions
from lowerduckpond_static_host_agent.host_restore_fence import require_source_fence
from lowerduckpond_static_host_agent.host_restore_gate import close_gate
from lowerduckpond_static_host_agent.host_restore_history import (
    import_prior_provenance,
    seal_provenance,
)
from lowerduckpond_static_host_agent.host_restore_inputs import (
    SUBJECTS,
    TRUST_BUNDLE,
    RestoreInputs,
    file_sha256,
)
from lowerduckpond_static_host_agent.host_restore_install import (
    install_roots,
    verify_installed_roots,
)
from lowerduckpond_static_host_agent.host_restore_ipc import request_archive
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_local import (
    LocalRecovery,
    finish_restored_jobs,
    local_work,
)
from lowerduckpond_static_host_agent.host_restore_locks import (
    recreate_kernel_locks,
    verify_kernel_locks,
)
from lowerduckpond_static_host_agent.host_restore_materialize import materialize_snapshot
from lowerduckpond_static_host_agent.host_restore_paths import RestorePaths
from lowerduckpond_static_host_agent.host_restore_runtime import (
    TrustedCaddy,
    prepare_restored_runtime,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import (
    RestoreSnapshot,
    inspect_restore_tree,
)
from lowerduckpond_static_host_agent.host_restore_tls import verify_cold_tls
from lowerduckpond_static_host_agent.host_restore_validation import validate_restored_authority
from lowerduckpond_static_host_agent.host_restore_verification import (
    verify_authorization,
    verify_installed_runtime,
    verify_settled_state,
)
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRepository

COORDINATOR_SECONDS = 30 * 60
CADDY_STORAGE = Path("/var/lib/caddy")


@dataclass
class HostRestore:
    """Caller holds repository EX, selected artifact SH and the root store lease."""

    store: RestoreStore
    snapshot: RestoreSnapshot
    inputs: RestoreInputs
    paths: RestorePaths
    environment: Mapping[str, str]
    selection_descriptor: int
    artifact_sha256: str
    caddy_uid: int
    destination_id: str
    fence: bytes
    deadline: float

    def _remaining(self) -> None:
        if time.monotonic() >= self.deadline:
            raise HostRestoreError("restore_coordinator_deadline")

    def _archive(self, action: str) -> dict[str, object]:
        self._remaining()
        return request_archive(
            self.store,
            self.selection_descriptor,
            self.artifact_sha256,
            action,
            recovery=self.paths.recovery,
        )

    def _repository(self, *, installed: bool = False, original: bool = False) -> StateRepository:
        materialization = self.paths.materialization
        state = self.paths.state if installed else materialization.roots["state"]
        content = self.paths.content if installed else materialization.roots["content"]
        return StateRepository(
            state,
            expected_owner=self.store.owner,
            tenant_release_root=content / "sites",
            recovery_root=materialization.roots["recovery"] if original else self.paths.recovery,
            private_reconciliation=True,
        )

    def _audit_paths(self, *, installed: bool = False) -> RotationPaths:
        return RotationPaths(
            root=self.paths.state if installed else self.paths.materialization.roots["state"],
            workspace=self.paths.materialization.workspace,
        )

    def _files(self) -> TrustedCaddy:
        return TrustedCaddy.load(
            self.inputs,
            root=self.paths.caddy,
            caddy_group=self.paths.caddy_group,
            owner=self.store.owner,
        )

    def _cold(self) -> None:
        require_cold_storage(
            self.store,
            CADDY_STORAGE,
            caddy_owner=self.caddy_uid,
            caddy_group=self.paths.caddy_group,
        )

    def run(self) -> RestoreJournal:
        self.inputs.require_destination(
            self.destination_id, self.artifact_sha256, self.snapshot.snapshot.snapshot_id
        )
        require_source_fence(self.fence, self.inputs, self.snapshot)
        current = self.store.read()
        if current is not None and current.phase is RestorePhase.COMPLETE:
            # Still compare all original bindings, without re-closing a finished
            # host whose ordinary tenant authority may already have advanced.
            current = self._begin()
            if not activation_pending(self.store):
                return current
        close_gate(self.store, self.inputs.restore_id)
        services.close_public_ingress()
        installed = current is not None and PHASES.index(current.phase) >= PHASES.index(
            RestorePhase.INSTALLED
        )
        services.quiesce_host(caddy=not installed)
        current = self._begin()
        self._cold()
        self.paths.prepare_parents()
        if current.phase in {RestorePhase.VERIFIED, RestorePhase.COMPLETE}:
            self._verify()
        while current.phase is not RestorePhase.COMPLETE:
            self._remaining()
            if current.phase is RestorePhase.PREPARED:
                receipt = self._materialize()
            elif current.phase is RestorePhase.RESTORED:
                receipt = self._validate()
            elif current.phase is RestorePhase.VALIDATED:
                receipt = self._reconcile()
            elif current.phase is RestorePhase.RECONCILED:
                receipt = self._runtime()
            elif current.phase is RestorePhase.RUNTIME_PREPARED:
                receipt = self._install()
            elif current.phase is RestorePhase.INSTALLED:
                receipt = self._verify()
            else:
                # A restarted VERIFIED phase was rechecked above; in one
                # invocation, the proof just acquired at INSTALLED suffices.
                receipt = {"provenanceInventory": seal_provenance(self.store)}
            next_phase = PHASES[PHASES.index(current.phase) + 1]
            current = self.store.advance(current, next_phase, receipt)
        activate_completed_restore(self.store, self.inputs, self.paths.caddy)
        return current

    def _begin(self) -> RestoreJournal:
        return begin_restore_authority(
            self.store,
            self.snapshot,
            self.inputs,
            self.fence,
            destination_id=self.destination_id,
            artifact_sha256=self.artifact_sha256,
        )

    def _materialize(self) -> dict[str, object]:
        self._files().require_inputs(self.inputs)
        filesystems = self.paths.materialization.filesystems()
        inspection = inspect_restore_tree(
            self.snapshot,
            self.environment,
            owner=self.store.owner,
            group=self.paths.caddy_group,
            fragments={
                label: value.fragment_size
                for label, value in filesystems.items()
                if label != "workspace"
            },
        )
        return materialize_snapshot(
            self.store, self.snapshot, self.paths.materialization, self.environment, inspection
        )

    def _validate(self) -> dict[str, object]:
        measured = validate_restored_authority(
            self.snapshot.descriptor,
            self.paths.materialization.roots,
            self.paths.materialization.workspace,
            owner=self.store.owner,
            content_group=self.paths.caddy_group,
            repository_genesis=self.snapshot.lineage,
            artifact_sha256=self.artifact_sha256,
            namespace=cast(dict[str, object], self.inputs.document["namespace"]),
            launch=cast(dict[str, object] | None, self.inputs.document["launch"]),
        )
        with self._repository(original=True) as repository:
            verify_authorization(repository, settled=False)
        return measured

    def _reconcile(self) -> dict[str, object]:
        import_prior_provenance(self.store, self.paths.materialization.roots["recovery"])
        descriptor = decode_backup_descriptor(self.snapshot.descriptor)
        files = self._files()
        try:
            self.store.read_bytes("audit-done.json")
        except FileNotFoundError:
            evidence = reconstruct_audit(
                self.store,
                self.snapshot,
                self._audit_paths(),
                self.environment,
                owner=self.store.owner,
                group=self.store.owner,
            )
            current = self.store.read()
            assert current is not None  # noqa: S101 - phase dispatcher
            self.store.immutable(
                "audit-done.json",
                canonical_json_bytes(
                    {
                        "schema": "lowerduckpond-host-restore-audit-done-v1",
                        "validatedJournalDigest": current.digest,
                        "evidence": evidence,
                    }
                ),
            )
        audit = verify_reconstructed_audit(
            self.store, self.snapshot, self._audit_paths(), self.environment
        )
        with self._repository() as repository:
            work = local_work(self.store, repository, descriptor)
        proof = self._archive("verify")
        state = self.paths.materialization.roots["state"]
        sites = self.paths.materialization.roots["content"] / "sites"
        with (
            self._repository() as repository,
            ExportSpool(state, expected_owner=self.store.owner) as spool,
            DeploymentReleaseStore(
                sites,
                sites / ".staging",
                expected_owner=self.store.owner,
                expected_release_group=self.paths.caddy_group,
                expected_staging_group=self.store.owner,
            ) as releases,
            spool.construction(),
        ):
            LocalRecovery(
                self.store,
                repository,
                spool,
                releases,
                CaddyBackupEvidence.from_dict(descriptor["caddy"]),
                files.original_ca,
                str(cast(dict[str, object], self.inputs.document["archiveTarget"])["bucket"]),
            ).reconcile(work, proof)
        # No export lease crosses the credential helper's own export exclusion.
        archives = self._archive("cleanup")
        with self._repository() as repository:
            finish_restored_jobs(self.store, repository, work)
            state_proof = verify_settled_state(
                repository,
                state,
                sites.parent,
                self.inputs,
                self.snapshot.lineage,
                owner=self.store.owner,
                content_group=self.paths.caddy_group,
            )
        return {
            "decisionsDigest": seal_decisions(self.store),
            "audit": audit,
            "archives": archives,
            "state": state_proof,
        }

    def _runtime(self) -> dict[str, object]:
        state = self.paths.materialization.roots["state"]
        with self._repository() as repository:
            mapping = prepare_restored_runtime(
                self.store,
                repository,
                self.paths.swaps["caddy"].candidate,
                state / "locks/publication.lock",
                decode_backup_descriptor(self.snapshot.descriptor),
                self.inputs,
                self._files(),
                caddy_uid=self.caddy_uid,
                caddy_gid=self.paths.caddy_group,
            )
        return {"runtimeMapping": mapping.digest}

    def _install(self) -> dict[str, object]:
        services.require_quiescent()
        roots = install_roots(self.store, self.paths.swaps)
        locks = recreate_kernel_locks(
            self.store, self.paths.state, self.paths.swaps["state"].container
        )
        return {"roots": roots, "locks": locks}

    def _verify(self) -> dict[str, object]:
        verify_installed_roots(self.store, self.paths.swaps)
        verify_kernel_locks(self.store, self.paths.state, self.paths.swaps["state"].container)
        self._cold()
        self._files().require_inputs(self.inputs)
        services.require_quiescent(caddy=False)
        self._capacity()
        audit = verify_reconstructed_audit(
            self.store, self.snapshot, self._audit_paths(installed=True), self.environment
        )
        archives = self._archive("verify-installed")
        with self._repository(installed=True) as repository:
            state = verify_settled_state(
                repository,
                self.paths.state,
                self.paths.content,
                self.inputs,
                self.snapshot.lineage,
                owner=self.store.owner,
                content_group=self.paths.caddy_group,
            )
            verify_installed_runtime(
                self.store,
                repository,
                self.paths,
                self.inputs,
                caddy_uid=self.caddy_uid,
                running=False,
            )
            services.start_caddy()
            runtime = verify_installed_runtime(
                self.store, repository, self.paths, self.inputs, caddy_uid=self.caddy_uid
            )
            tls = self._tls()
            if (
                verify_installed_runtime(
                    self.store, repository, self.paths, self.inputs, caddy_uid=self.caddy_uid
                )
                != runtime
            ):
                raise HostRestoreError("restore_runtime_changed_during_tls_proof")
        return {
            "state": state,
            "runtime": runtime,
            "tls": tls,
            "audit": audit,
            "archives": archives,
        }

    def _capacity(self) -> None:
        for path in (self.paths.state, self.paths.content, self.paths.caddy, CADDY_STORAGE):
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(0, 0),
                measure_filesystem_capacity(path),
            )

    def _tls(self) -> dict[str, object]:
        if (
            file_sha256(
                TRUST_BUNDLE,
                owner=self.store.owner,
                group=self.store.owner,
                mode=0o644,
                maximum=16 * 1024 * 1024,
            )
            != self.inputs.caddy["trustBundleSha256"]
        ):
            raise HostRestoreError("restore_public_trust_changed")
        while True:
            self._remaining()
            try:
                return verify_cold_tls(
                    CADDY_STORAGE / "caddy/certificates",
                    issuer=str(self.inputs.caddy["issuer"]),
                    subjects=SUBJECTS,
                    trust=TRUST_BUNDLE,
                    owner=self.caddy_uid,
                    group=self.paths.caddy_group,
                    trust_owner=self.store.owner,
                )
            except FileNotFoundError:
                pass  # Issuance has not yet populated its cold storage.
            except HostRestoreError as error:
                if str(error) not in {
                    "restore_tls_peer_unavailable",
                    "restore_tls_peer_unverified",
                    "restore_tls_subjects_unavailable",
                }:
                    raise
            # Observe acquisition under the existing deadline; never restart
            # Caddy, clear account state, reset failures or extend that deadline.
            time.sleep(min(5, max(0, self.deadline - time.monotonic())))
