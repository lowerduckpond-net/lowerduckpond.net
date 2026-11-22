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

## Evidence still required

The component tests exercise pinned client configuration, deterministic
staging, state and provider substitutions, native readback, and the existing
activation gates. The real journey still needs authenticated provider
captures, protected host-key provisioning, an accepted M3.11 source, a
separately owned restore and fresh target, and installed proof through
reboot, exact archive versions, ingress, and cleanup. Provider operations
and edge and storage exercises require their own reviewed disposable
authorization.
