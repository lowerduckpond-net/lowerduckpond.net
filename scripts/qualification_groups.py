"""Fixed installed groups; selection never accepts arbitrary tests or commands."""

from __future__ import annotations

from dataclasses import dataclass

GROUP_REPORT_FORMAT = "lowerduckpond-installed-group-diagnostic-v1"

ACCOUNTING = (
    "test_archive_completion.py::test_installed_archive_qualification_has_no_unresolved_accounting"
)


def node(module: str, name: str, parameters: str = "") -> str:
    return f"tests/test_{module}.py::test_{name}[{{host}}{parameters}]"


@dataclass(frozen=True)
class Group:
    tests: tuple[str, ...]
    after_reboot: tuple[str, ...] = ()
    reconstruction: bool = False
    protected_history: bool = False

    @property
    def phases(self) -> tuple[str, ...]:
        # Reconstruction checks the fully activated source inside verify and
        # requires its bound receipt. Other groups check initial idempotence.
        idempotence = () if self.reconstruction else ("idempotence",)
        return ("create", "prepare", "converge", *idempotence, "verify")

    def nodes(self, stage: str, host: str) -> tuple[str, ...]:
        accounting = (
            node("restore_accounting", "installed_restore_paired_accounting")
            if self.reconstruction
            else f"tests/{ACCOUNTING}[{{host}}]"
        )
        if stage == "before" and self.after_reboot:
            tests = self.tests
        elif stage == "after" and self.after_reboot:
            tests = (*self.after_reboot, accounting)
        elif stage == "run" and not self.after_reboot:
            tests = (*self.tests, accounting)
        else:
            raise ValueError("unsupported installed group stage")
        return tuple(value.format(host=f"docker://{host}") for value in tests)

    @property
    def stages(self) -> tuple[str, ...]:
        return ("before", "after") if self.after_reboot else ("run",)


_CREDENTIALS = "archive_credentials"
GROUPS = {
    "production-rollout": Group(
        (node("production_rollout", "installed_production_rollout_preserves_original_evidence"),)
    ),
    "combined-reconstruction": Group(
        (node("combined_reconstruction", "installed_combined_reconstruction"),),
        reconstruction=True,
        protected_history=True,
    ),
    "restore-reconstruction": Group(
        (node("restore_reconstruction", "installed_restore_reconstruction"),),
        reconstruction=True,
        protected_history=True,
    ),
    "restore-negative": Group(
        (node("restore_negative", "installed_restore_negative"),), reconstruction=True
    ),
    "restore-tls-bootstrap": Group(
        (node("restore_tls_bootstrap", "installed_restore_tls_bootstrap"),), reconstruction=True
    ),
    "audit-rotation": Group(
        (node("audit_rotation", "installed_rotation_interruptions_before_reboot"),),
        after_reboot=(node("audit_rotation", "installed_rotation_reboot_and_second_full_segment"),),
    ),
    "audit-protection": Group(
        (
            node(
                "audit_protection",
                "installed_audit_protection_reconciles_orphans_and_preserves_retention",
            ),
        )
    ),
    "backup-coherence": Group(
        (node("backup_coherence", "installed_coherent_backup_restore_and_writer_exclusion"),)
    ),
    "backup-mutation-overlap": Group(
        (node("backup_coherence", "installed_backup_capture_races_mutations"),)
    ),
    "backup-identity": Group(
        (node("backup_identity", "installed_backup_identity_migration_and_repository_fencing"),)
    ),
    "core": Group(
        (node("core_independent", "core_lifecycle_without_configuration_guard_repetition"),)
    ),
    "configuration-publication": Group(
        (
            node(
                "configuration_independent",
                "publication_and_operator_boundaries_preserve_the_live_tenant",
            ),
        )
    ),
    "configuration-generation": Group(
        (
            node(
                "configuration_independent",
                "generation_input_and_idempotence_preserve_the_live_tenant",
            ),
        )
    ),
    "export-roundtrip": Group(
        (node("export_import", "installed_full_size_export_import_round_trip"),)
    ),
    "export-recovery": Group(
        (
            node("export_import", "installed_unacknowledged_retry_conflict_and_expiry"),
            node("export_import", "installed_capture_races_core_mutations_and_release_cleanup"),
        )
    ),
    "archive-cycles": Group(
        (node("archive_independent", "archive_cycles_capture_recovery_and_retirement"),)
    ),
    "full-size-archive": Group((node("archive_full_size", "fresh_full_size_archive_restore"),)),
    "deletion-quarantine": Group(
        (
            node("deletion", "installed_ordinary_and_emergency_deletion"),
            node("deletion", "installed_emergency_recovery_retires_the_exact_archived_version"),
            node("quarantine_recovery", "installed_terminal_retry_reopens_only_proven_quarantine"),
        )
    ),
    "transport-recovery": Group(
        (node("recovery_independent", "admission_transport_and_caddy_failure_recovery"),)
    ),
    "overlap-deployment": Group(
        (node("recovery_independent", "configuration_overlap_with_deploy_rollback_and_suspend"),)
    ),
    "overlap-routing": Group(
        (node("recovery_independent", "configuration_overlap_with_resume_rename_and_reconcile"),)
    ),
    "reboot-journey": Group(
        (
            node("cross_feature", "cross_feature_before_reboot"),
            node("reboot", "capture_installed_reboot_state"),
        ),
        (
            node("reboot", "verify_installed_reboot_state"),
            node("cross_feature", "cross_feature_after_reboot"),
        ),
    ),
    "credentials": Group(
        (
            node("archive_lifecycle", "installed_tls_storage_credentials_are_mutually_denied"),
            node(_CREDENTIALS, "installed_ordinary_reconciler_cannot_connect_to_archive_services"),
            *(
                node(
                    _CREDENTIALS,
                    "installed_reconciler_masks_entries_created_after_namespace_start",
                    f"-{mode}",
                )
                for mode in (False, True)
            ),
            *(
                node(
                    _CREDENTIALS,
                    "installed_archive_credentials_stay_inside_the_network_boundary",
                    f"-{kind}",
                )
                for kind in ("export", "construction", "cleanup")
            ),
            *(
                node(
                    _CREDENTIALS,
                    "installed_ordinary_units_cannot_see_archive_credentials",
                    f"-{unit}",
                )
                for unit in (
                    "lowerduckpond-backup.service",
                    "lowerduckpond-backup-maintenance.service",
                    "lowerduckpond-backup-identity.service",
                    "lowerduckpond-audit-initialize.service",
                    "lowerduckpond-audit-verify.service",
                    "lowerduckpond-audit-rotate.service",
                    "lowerduckpond-static-reconcile.service",
                    "lowerduckpond-static-worker@.service",
                )
            ),
            node(
                _CREDENTIALS,
                "installed_emergency_recovery_clears_quarantine_without_a_remaining_intent",
            ),
            node(_CREDENTIALS, "installed_idle_emergency_recovery_needs_no_archive_credentials"),
            *(
                node(
                    _CREDENTIALS,
                    "installed_credentials_drain_ordinary_processes_using_the_previous_isolation",
                    f"-{mode}-{unit}",
                )
                for mode in (False, True)
                for unit in (
                    "lowerduckpond-backup.service",
                    "lowerduckpond-backup-maintenance.service",
                    "lowerduckpond-backup-identity.service",
                    "lowerduckpond-audit-initialize.service",
                    "lowerduckpond-audit-verify.service",
                    "lowerduckpond-audit-rotate.service",
                    "lowerduckpond-static-reconcile.service",
                )
            ),
            node(
                _CREDENTIALS,
                "installed_empty_configuration_withdraws_existing_archive_credentials",
                "-None-False",
            ),
            *(
                node(
                    _CREDENTIALS,
                    "installed_empty_configuration_withdraws_existing_archive_credentials",
                    f"-{kind}-{mode}",
                )
                for kind in ("export", "construction", "cleanup", "emergency")
                for mode in (False, True)
            ),
            node(_CREDENTIALS, "installed_legacy_selection_disables_only_the_new_service_family"),
        )
    ),
}
