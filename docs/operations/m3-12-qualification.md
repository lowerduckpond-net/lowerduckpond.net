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
gates. The real journey still needs authenticated provider captures,
protected host-key provisioning, an accepted M3.11 source, and separately
owned restore and fresh targets. The real-host evidence has to cover actual
host reboot, archive versions, ingress, capacity, and cleanup. Provider
operations and edge and storage exercises require their own reviewed
disposable authorization.
