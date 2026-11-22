# M3.12 evidence inventory

The [versioned inventory](../../schemas/m3-12/v1/requirements.json) maps
76 source paragraphs or individual list items from ADR 0022’s Decision and
Consequences, the parent M3.12 phase and the milestone completion criteria to 176
environment-specific proof slots. Each requirement has a stable ID, source
heading, and SHA-256 of the normalized paragraph text. The proof slots inherit
their requirement ID and name the environment. When a source paragraph changes,
retain its ID, re-review its proof, and update its fingerprint in the same
candidate. For a new paragraph allocate a new ID.

A mapped slot names exact pytest nodes as existing test anchors. A mapped
component slot can establish only the behavior those nodes actually cover.
For a paragraph with multiple obligations, extend the mapping to the remaining
exact tests and evidence at the stated environments before accepting it.
Pending slots name the responsible slice and have no passing result. During
P1 the inventory and contract vectors establish interpretation and reject
unsupported authority. P2–P6 complete the actual path, node and evidence
mappings when those behaviors exist.

| Evidence | Exact P1 assertion or later scope |
| --- | --- |
| Kind/purpose/role and immutable binding | [Paired admission vectors](../../tests/infrastructure/test_m3_12_contracts.py) `test_three_paired_admissions_and_existing_launch_record`, `test_target_substitution_rejected_even_when_rehashed`, `test_crossover_cannot_be_selected_by_an_argument_or_mixed_pair`. P3/P4 exercise the same real initializer in the exact owned installed and Droplet environments. |
| Prior live proof and acyclic ordering | `test_untrusted_swapped_cross_target_and_future_receipts_are_rejected`, `test_completed_installed_report_cannot_satisfy_production`, `test_same_invocation_preflight_and_final_backup_are_required`. P4 supplies the actual provider and restore observations and P6 reads fresh production facts. |
| Durable launch, history and crash boundaries | `test_journal_crash_resumes_original_intent_and_refuses_replay`, `test_rollback_requires_exact_scope_and_zero_history_even_with_no_current_tenants`. P3/P4 inject interruption at actual write/sync/restart boundaries and exercise backup and restore with history. |
| Diagnostics through the actual transport | `test_diagnostics_distinguish_missing_terminal_primary_and_secondary`. [P2 local regressions](../../tests/infrastructure/test_m3_12_diagnostics.py) cover early allocation, original result, export conflicts, interruption and raw output exclusion. The [installed transport-recovery witness](../../config/ansible/molecule/m3_8/tests/test_m3_12_diagnostics.py) exercises systemd through real Ansible and Docker and verifies console, private and public exclusion on the same synthetic fixture. |
| Original chronology and evidence inventory | `test_delayed_packaging_does_not_refresh_original_evidence`, `test_inventory_covers_every_source_paragraph_and_rejects_stale_or_missing_entries`, `test_exact_requirement_coverage_rejects_missing_skipped_duplicate_and_installed_proof`. P4/P5/P6 produce the original phase, accounting, teardown and acceptance receipts. |

The P4 [controller tests](../../tests/infrastructure/test_m3_12_droplet_controller.py)
check protected cold-restore inputs and same-host readback in
`test_cold_restore_preflight_binds_the_original_policy_to_the_two_owned_hosts`.
`test_fresh_dark_readback_requires_the_pinned_candidate_after_reboot` checks
dark-state admission and original receipt retention across simulated boot
observations. The [launch contract tests](../../tests/infrastructure/test_m3_12_contracts.py)
include `test_reconstructed_launch_provenance_does_not_grant_destination_publication`
for independent enrollment and
`test_cold_restore_provenance_requires_the_original_launch_and_source_scope`
for the source launch chain, artifact and namespace. The [native recovery
tests](../../packages/static-host-agent/tests/test_host_restore_droplet.py)
check dark and launched activation, destination drift before publication,
and bound ingress recovery after interruption. These tests supply component
evidence. Provider, independent restore, and real reboot
slots still require their own original receipts.

The [installed restore case](../../config/ansible/molecule/m3_8/tests/test_restore_reconstruction.py)
checks that a copied Droplet bundle cannot promote its Docker destination
while the ordinary installed restore can still complete. The
[initial retirement tests](../../tests/infrastructure/test_m3_12_droplet_plan.py)
`test_retirement_review_validates_only_original_deletions` and
`test_interrupted_retirement_requires_exact_independent_absence` cover
foreign deletes and interrupted cleanup at the component layer. The
[disposable preparation guide](../operations/m3-12-qualification.md) names the
remaining real-host and provider proofs.

The controller retains pinned guest observations by digest and records the
scoped inputs of each native install handoff. Hermetic SSH tests prove that
read-only preparation can resume after a lost connection and reboot without
changing the first observation. They also exercise the closed capacity
sample format and verify hard-link deduplication on a local filesystem.
These observations need the actual authorized workload and provider
receipts before they can support real-host capacity or journey completion.

The [inventory validator](../../scripts/m3_12_requirements.py) checks source
coverage, fingerprints, unique requirements/slots and existing mapped test
nodes. The versioned requirement-proof binds the reviewed inventory, exact
slot and nodes, original immutable evidence, independently selected target
and original clock. The coverage gate rejects missing, skipped, stale, wrong
target and duplicate records. Disposable closure consumes component,
installed, Droplet, independent restore and disposable browser evidence.
Production closure adds independently bound live preflight, read-only edge
and canary evidence. A component or installed result cannot occupy a live
or restore slot. An original execution proof may support multiple requirements
if it explicitly asserts each and each slot has its own bound receipt.
