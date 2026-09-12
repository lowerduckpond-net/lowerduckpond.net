# M3.9 export and portable-import evidence

Status: completed on 2026-09-10. The combined implementation passed 1,982
Python tests with the expected unconfigured-MinIO skip. The complete disposable
host scenario passed convergence, idempotence, core lifecycle, M3.9 qualification,
exact persisted-state comparison after reboot, transport/recovery, and cleanup.

A local 5,000-entry, 100-MiB-content export produced a 106,128,870-byte
bundle in 6.36 CPU seconds with 104.4 MiB peak resident memory, under a
256-MiB process address-space limit and a 120-second CPU limit. That
construction measurement uses fixture-supplied capacity probes; the installed
suite below verifies the actual filesystem reserve and worker cgroup limits.

[Generation admission tests](../../packages/static-host-agent/tests/test_caddy_generation.py)
also publish and reopen fresh and derived configuration and routing metadata
larger than 16 KiB using their existing 2-MiB aggregate bounds. This covers the
metadata growth from imported provenance without changing individual contract
limits. A preserved installed import with 17,667-byte routing metadata recovered
its prepared transaction under the configured worker limits, retaining the
original target and deployment IDs, provenance, and exact result replay.

The invariant numbers below refer to
[the static-publication threat model](static-publication.md). This phase adds
no remote archive operation. Spaces version binding, archived export, and
archive/restore/deletion races remain in M3.10. Production publication remains
disabled.

Routine production convergence completed on 2026-09-12 from source revision
`90b0353bd89328730e49c57babd8dc9d17d849aa`, selecting host-agent artifact
SHA-256
`4e32c4a88d729b371b8cd5da96e5fedbc9f30266acb0984599c1d645939bef85`.
The operator reported final acceptance with `ok=20`, `changed=0`,
`unreachable=0`, and `failed=0`, after the guarded runner required its preflight
and zero-change second convergence. Acceptance verified the selected artifact,
disabled publication gate, encrypted backup, and disposable restore. A
subsequent read-only check confirmed the selected artifact path. The
[host configuration runbook](../operations/host-configuration.md) records this
production checkpoint; export/import qualification uses the disposable host.

| Changed invariant | Unit and process evidence | Installed-host evidence | Recovery evidence |
| --- | --- | --- | --- |
| Coherent independent capture; ordered locks (12, 16, 20) | [Snapshot tests](../../packages/static-host-agent/tests/test_export_snapshot.py) verify exact active/suspended manifests and deployment records, independent inodes, sealed modes, shared-lock exclusion, source drift, and unsafe files. | [Export/import qualification](../../config/ansible/molecule/m3_8/tests/test_export_import.py) overlaps installed capture with real deploy, rollback, suspend, resume, rename, and reconcile workers. Rollback removes the captured source release before bundle construction. | Real process death at every capture hook leaves only bounded private work; a new capture cleans it and reconstructs the same authority. |
| Bounded spool, state, and output; deterministic construction (16, 24) | [Handler tests](../../packages/static-host-agent/tests/test_export_handler.py) fill spool byte/inode and result record/byte limits before publication, reject an occupied slot, and compare repeated bundle bytes. Snapshot tests cover host reserve and physical accounting, including interrupted builder links. | The installed test deploys 5,000 entries with 104,857,600 content bytes and performs active/suspended exports and imports under the configured 256 MiB memory, zero swap, one-CPU quota, and 120-second CPU limit. Repeated exports must be byte-identical, including after an import into another tenant selects a newer shared routing generation while the source observation stays unchanged. | Real process death at all eight export commit boundaries yields one audit entry and immutable result; incomplete construction is removed and committed publication is recovered. |
| Authenticated bounded delivery and retirement (16, 26, 32) | [Handler tests](../../packages/static-host-agent/tests/test_export_handler.py), [runtime tests](../../packages/static-host-agent/tests/test_job_runtime.py), [adapter tests](../../packages/static-host-agent/tests/test_operator_adapter.py), and [client tests](../../tools/static-operator/tests/test_client.py) cover exact principal/job/digest/size binding, fixed binary framing and EOF, client durability, and fixed expiry. | The installed test verifies terminal undeployed-export rejection and SSH download/acknowledgement, unacknowledged exact retries, second-export conflict, accepted-time expiry, and immutable results with no payload after retirement. | Header, result, and payload disconnects close the source while holding export exclusion and retain exact retry bytes. Spawned processes verify that download start, download completion, acknowledgement, and cleanup wait for competing shared or exclusive tenant-state holders. Real process death at both retirement boundaries resumes from the synced marker without rewriting the result. |
| Import preserves target identity and policy (12, 22, 25, 27, 30, 31, 32) | [Deployment commit tests](../../packages/static-host-agent/tests/test_deployment_commit.py) run actual bundle intake, authorization, extraction, publication, execution, and replay for active/suspended/archived provenance, including stricter target quotas and terminal byte/entry quota rejection before intent creation. [Artifact execution tests](../../packages/static-host-agent/tests/test_execution.py) reject omitted provenance. | The installed round trip imports active and suspended exports into different undeployed targets, checks new deployment IDs and target origins, rejects the full bundle against a smaller target quota, verifies provenance, and serves exact content through Caddy. | Real process death after the import intent recovers through the ordinary deployment transaction, including source-provenance reconstruction, selected release, terminal result, and intake/intent cleanup. Existing deployment commit-boundary tests cover the shared durable transaction. |

Run the complete installed suite with `just check-ansible-m3-8`. Its existing
scenario name is retained; it now includes M3.9 qualification before the
persisted-state capture and reboot, so imported tenants also pass the normal
boot-recovery comparison. The scenario uses disposable local sshd, systemd,
Caddy, and filesystem state, with actual resource limits and authenticated
operator transport. It does not exercise or enable production publication.
