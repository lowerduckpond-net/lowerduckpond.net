# M3.12 disposable host preparation

P4 prepares a source, an independent cold restore destination, and a separate
fresh host. Their roles use distinct state keys, provider identities, and
SSH pins. This workflow depends on independently approved provider captures
and has no routine for applying a plan or obtaining credentials.

## Allocation and transport

The [initial plan guard](../../scripts/m3_12_droplet_plan.py) checks the
reviewed saved-plan JSON. The [readback adapter](../../scripts/m3_12_droplet_provider.py)
takes exact plan and OpenTofu state JSON digests from reviewed custody, the
approved per-role state key, and an independently gathered provider projection.
That projection contains the active Droplet's identity and size, its exact
project membership, and its one attached firewall with settled reviewed
rules. Capture rule lists only after the provider confirms there are no
pending changes. The adapter checks these facts against state and the
production exclusions before it constructs an allocation. A separately
authenticated provisioning channel must supply the host's Ed25519 key.

Keep the controller attempt private. The controller opens the approved
numeric address using only the supplied host key and client identity.
The fresh and restore handoffs produce one-host inventories for the native
site playbook, a private known-hosts file, and fixed dark stage variables.
The restore handoff also pins the exact original artifact, native restore
ID, and scoped delivery directory. The operator supplies reviewed site
inputs separately, including the original backup node name and repository.

## Reviewed allocation and journey runner

The [allocation checker](../../scripts/m3_12_droplet_scope.py) takes a
canonical `droplet-journey-allocation` manifest and a separate
`ReviewedJourney` from trusted custody. The review supplies the approved
manifest digest, complete original M3.11 journal, reviewed historical
bootstrap and site policy digests, exact candidate record, independent
resource readback, and production exclusions. Keep credential bytes in
their existing independent custody. The manifest is bound to the exact
controller attempt. It contains only the closed non-secret scope.

| Resource | Binding |
| --- | --- |
| Source, restore and fresh host | Role-specific state key, enrolled target, SSH fingerprint, address, and reviewed admin CIDRs. Each host and its state/lease identities are distinct. |
| Platform and tenant edge | Two separately owned disposable zones on distinct registrable domains, each with a source name scope and a disjoint fresh name scope, and exact primary and replacement certificate IDs. The scopes cover the reviewed names and their descendants. Restore uses the source scope only after the original source is fenced. |
| Restic and archive | Exact Spaces region, bucket and prefix. Restic and archive buckets are distinct, and fresh uses a separate pair. Restore reads the exact source resources. Cleanup remains subject to the original ownership and retirement rules. |

Verify the host facts through the existing plan/readback and pinned SSH
adapters. The independent edge readback must bind the actual owned zone
names, registrable domains and certificate associations. The independent storage readback
must bind the actual bucket and prefix, including archive inventory scope.
The runner refuses missing review inputs, stale or substituted scope, and
overlap with the supplied production exclusions before making any adapter call.

`run_journey(attempt, allocation_bytes, reviewed, driver)` runs the
[fixed phase sequence](../../scripts/m3_12_droplet_journey.py) through a
driver supplied by the caller. An adapter's `submit` uses the original
scope, native lease and exact named phase. Its separate `readback` reports
the independently observed outcome and digests of the original evidence.
The runner checks the receipt against the durable intent and required phase
evidence. There is no command or adapter selection in the manifest.

A lost caller leaves a pending intent. Reopen the same attempt for readback;
dependent steps remain blocked while independent eligible steps can proceed.
For a phase with a recorded no-effect result, an explicit
`retry_not_applied=PHASE` requires fresh no-effect readback and records a new
dispatch linked to the first. Original intents, failures and receipts are
retained. Teardown depends on independently reopened original evidence.
Sequence completion describes the adapter workflow only. It supplies no
real-host or production qualification receipt.

## Native adapter checks

The [native boundary](../../scripts/m3_12_droplet_native.py) reopens the
approved allocation and exact persisted phase intent before preparing
a command. SSH reads use the same explicit host key and independently
recheck the full enrolled guest identity. Restore readback opens the protected
delivery through the existing destination adapter and requires its original
target before reading either native command result.

The Ansible preview reopens the one-host inventory, known-hosts file, and
dark stage file under the original handoff digests. It rederives the stage
from the authorized artifact or protected restore policy. The command
selects only the owned host and uses `site.yml --list-hosts`. Native apply
is blocked. The immutable Caddy route builder emits production apex and
wildcard subjects and the tenant contracts still pin the production
canonical suffix. The legacy `caddy_domain` variable does not change those
paths.

The [edge adapter](../../scripts/m3_12_droplet_edge.py) builds exact browser
origins, apex and wildcard subjects, and origin-pull identity inputs from
the manifest and original functional tenant fixture. Independent readback
must match both approved zone IDs and names, strict SSL, Always Online off,
proxied origin addresses and the expected certificate generation. The existing
browser assertions accept the prepared disposable scopes. Their historical
entry point keeps its existing host set.

The [storage adapter](../../scripts/m3_12_droplet_storage.py) derives the
regional HTTPS endpoint and exact bucket from the verified manifest. Restore
maps to the original source resources. The Restic locator uses the reviewed
prefix. The archive namespace is the native `archives/` prefix in a dedicated
bucket. Full-bucket inventory retains evidence of foreign names, versions,
delete markers and uploads. Restore rereads the original archive authority
and uses the native exact-version verifier. The injected client must be a
reader for that exact scoped bucket.

## Restore delivery and readback

Cold preparation binds trusted policy and the original source fence to both
enrolled hosts. For a launched snapshot, retain the original source
admission, launch intent, and launch receipt in the reviewed input custody.
The controller stages only the native policy, fence, original CA, destination
enrollment, production exclusions, and any original source launch chain.
Exact replay keeps the original protected bytes.

The native role closes recovery ingress before installing the publication
view. A retained file must already have the expected bytes, owner and mode.
The role rereads the delivered digests using the verified installed artifact
and the destination's actual enrollment. The native coordinator requires
that proof before working on a scoped restore. The controller can also
join the fixed native delivery and status readbacks across the same pinned
host and boot. The resulting observation stays private and carries no
qualification or publication authority by itself.

## Installed destination witness

The existing `restore-reconstruction` group already runs a fenced source
and a distinct cold destination through real Ansible, Restic, systemd and
installed archive reconciliation on the owned Docker and MinIO fixture.
It checks closed ingress from a peer before recovery, exact restored state
and archive readback, and completed recovery after a destination restart.

The [installed destination test](../../config/ansible/molecule/m3_8/tests/test_restore_reconstruction.py)
also passes an internally consistent copied Droplet bundle to the actual
verified installed artifact. The native workstation-style record checks
accept the bundle and the destination readback rejects its Docker identity.
This probe uses a private disposable path and leaves the real restore
policy, fence and publication view untouched. The test rechecks closed
ingress, then finishes the existing restore journey.

A positive Droplet delivery, launch, activation, or reboot receipt requires
a real independently enrolled host. The installed fixture continues to
produce evidence for native restore behavior and rejection of copied
authority. Its container restart and MinIO observations occupy installed
proof slots only.

## Original observations and interrupted preparation

The controller keeps the first source and destination observations and their
scope immutable. If the SSH caller loses the result while preparing the pair,
repeat the read-only preparation using the same attempt, endpoints and
exclusions. The controller rechecks the original host identity and installation
state. A changed boot can be recorded separately when those checks agree.
A changed host or installation state requires investigation before continuing.

Later boot, dark install and restore readbacks retain the original closed guest
record under its content digest. The private install handoff receipt also binds
the inventory, stage variables and known-hosts file to the original target.
A successful readback records only what the host reported at that point. Recover
a lost Ansible or native action result from the original task or journal before
submitting another mutation.

## Capacity samples

The controller's `inspect_capacity` operation samples an enrolled host through
the same pinned SSH endpoint. Each private sample binds the original target,
realized platform and selected artifact, boot identity and monotonic interval.
It records memory headroom, swap and OOM counters, CPU pressure, the ordinary
block and inode view excluding root reserve, and readable cgroup counters and
limits. Absent service cgroups and unavailable optional counters remain null.
Cgroup memory peaks include kernel-accounted memory such as file cache.

Take allocation samples separately from the faster point reads. The allocation
sample walks the release filesystem to count blocks and inodes with each
hard-linked inode counted once. Use these reads at workload boundaries so the
tree scan does not dominate the overlapping workload. Qualification still needs
a correlated measurement of the approved overlapping workload, process RSS,
enforced worker and parser limits, and actual block and inode reserve outcomes.

## Initial allocation teardown review

The [retirement guard](../../scripts/m3_12_droplet_cleanup.py) captures the
original review, state and independent provider facts for one initial host.
It checks an independently reviewed destroy-plan digest and role-specific
state key, matches the original resource bytes, and accepts only deletion
of that exact Droplet, attached firewall and project membership. A changed
allocation or additional resource needs a new reviewed disposition.

If a caller loses the result, retain the original allocation and plan
and reconcile the exact state key and provider identities. The offline
reconciler requires the observed state digest and independent absence of
the Droplet, firewall and project membership before it records absence.
Any surviving or unverified observation remains unresolved. This covers the
initial host allocation. Edge, DNS, archived objects, credentials, and
their own teardown evidence remain separate obligations.

The [journey teardown adapter](../../scripts/m3_12_droplet_teardown.py)
reopens the scope and cleanup authority retained with the original evidence
before accepting a per-host destroy plan. Its reconciliation joins the three
native host absence proofs with independent DNS, storage and original grant
observations. Unverified or surviving resources stay unresolved. A designated
archive retention requires the original custody evidence, even if the
corresponding bucket is now absent. The adapter verifies observations and
prepares no provider deletions.

## Evidence still required

The component tests exercise pinned client configuration, deterministic
staging, state and provider substitutions, native readback, and activation
gates. The remaining real-host journey needs authenticated provider captures,
protected host-key provisioning, an accepted M3.11 source with its exact
bootstrap inputs, and separately owned restore and fresh targets.

The dependency runner and adapter boundaries are exercised offline.
[ADR 0023](../adr/0023-separate-reusable-slugs-from-tenant-origins.md#disposable-qualification-exception)
permits one disposable HTTPS presentation for each specifically enrolled
test tenant. The reviewed site policy pins the exact derived origins and
the two owned domain scopes. The native renderer projects only HTTP matchers,
redirect targets, logging names and TLS subjects. It retains the original
logical route-state digest separately from the projected generation digest.

The source and cold destination must reopen the same allocation and
presentation. The controller seals the cutover only after it verifies
the original restore fence and observes the exact native drop rule on both
pinned boots and inactive source Caddy. It refuses future source projection
and requires the matching cutover before preparing the destination payload.
The browser proof distinguishes retained local storage from a new TLS
request. The pinned SSH probe correlates its unique marker to one Caddy
access entry in the restored host's current boot. Only the proof fields
leave the guest. Raw journal entries and request headers stay on the host.

The ordinary Ansible apply refusal is still active. Native provisioning,
delivery of protected routing authority to the installed service and actual
provider proof need their own verified handoff. This offline suite exercises
generation selection under the exact projected scope and tests the controller
boundary and browser protocol with synthetic transport. The qualification
root presently owns only the initial host resources.

The real-host sequence remains to be proven from the accepted predecessor
through upgrade, interruption and reboot, the full lifecycle and actual
Spaces access, and a separate cold restore with exact archive versions,
closed ingress and original evidence retained before teardown. The independent
fresh installation needs its own receipts. Provider operations and edge and
storage exercises require reviewed disposable authorization.
