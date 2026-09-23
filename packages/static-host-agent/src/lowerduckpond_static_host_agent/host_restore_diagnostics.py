"""Fixed restore categories; exception messages and remote coordinates stay private."""

from lowerduckpond_static_host_agent.archive_diagnostics import archive_failure_diagnostic
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

CATEGORIES = frozenset(
    {
        "restore_archive_ambiguous",
        "restore_required_archive_unavailable",
        "restore_later_remote_timeline",
        "restore_remote_inventory_changed",
        "restore_required_archive_manifest_unavailable",
        "restore_archive_authority_mismatch",
        "restore_target_input_mismatch",
        "restore_trusted_input_mismatch",
        "restore_source_fence_mismatch",
        "restore_source_fence_incomplete",
        "restore_coordinator_deadline",
        "restore_trusted_file_unsafe",
        "restore_trusted_file_changed",
        "restore_tls_certificate_invalid",
        "restore_tls_key_mismatch",
        "restore_tls_chain_or_validity_invalid",
        "restore_tls_storage_changed",
        "restore_tls_trust_changed",
        "restore_tls_subjects_unavailable",
        "restore_tls_peer_unverified",
        "restore_tls_peer_unavailable",
        "restore_tls_storage_unsafe",
        "restore_tls_trust_unsafe",
        "restore_tls_storage_limit",
    }
)


def diagnostic(error: Exception) -> str:
    category = str(error) if isinstance(error, HostRestoreError) else ""
    if category not in CATEGORIES:
        category = "restore_unverified"
    return category + " " + archive_failure_diagnostic(error)
