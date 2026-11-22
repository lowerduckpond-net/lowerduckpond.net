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

## Evidence still required

The component tests exercise pinned client configuration, deterministic
staging, state and provider substitutions, native readback, and activation
gates. The remaining real-host journey needs authenticated provider captures,
protected host-key provisioning, an accepted M3.11 source with its exact
bootstrap inputs, and separately owned restore and fresh targets.

A Droplet pin constrains the SSH target. The native site playbook also consumes
DNS, origin-pull and backup configuration. Before wiring an executable
convergence sequence, bind those inputs to reviewed disposable DNS names,
certificate and zone identities, and separate Restic and archive resources.
The qualification root currently owns only the initial host resources.
The existing edge/browser tools pin their historical M3 names. The P4
adapter needs an explicit owned name layout and independent provider readback
before it can exercise issuance, rollover and browser behavior safely.

The real-host sequence remains to be proven from the accepted predecessor
through upgrade, interruption and reboot, the full lifecycle and actual
Spaces access, and a separate cold restore with exact archive versions,
closed ingress and original evidence retained before teardown. The independent
fresh installation needs its own receipts. Provider operations and edge and
storage exercises require reviewed disposable authorization.
