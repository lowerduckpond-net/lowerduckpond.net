# M3.12 installed diagnostics

`just m3-12 run transport-recovery` runs an existing installed qualification
group with a fresh local Docker and MinIO fixture. The launcher prints its
private attempt path before parsing the group or syncing dependencies.
Use the original, unmodified path for follow-up. The default root is
`${XDG_DATA_HOME:-$HOME/.local/share}/lowerduckpond.net/m3-12`.
`LDP_M3_12_DIAGNOSTIC_ROOT` can select a private root on persistent storage.

| Follow-up on the printed attempt path | Behavior |
| --- | --- |
| `just m3-12 status PATH` | Show the original status, shareable summary location, uncertainty and next command. |
| `just m3-12 inspect PATH` | List durable controller and transferred guest checkpoints and separate failure roles. |
| `just m3-12 collect PATH` | Export the closed summary from recorded original evidence. An interrupted observer with no original terminal outcome yields an unknown result. |
| `just m3-12 collect PATH --guest start` | Collect the start checkpoint from an instrumented, retained guest under the original fixture lease. Use `--guest result` for a terminal checkpoint. |
| `just m3-12 debug PATH` | Verify the original local daemon, fixture ID and guest system state. |
| `just m3-12 debug PATH --shell` | Open an attended shell in the bound disposable systemd guest and mark subsequent observations diagnostic-only. Scheduled cleanup and original ownership exclusion still apply. |
| `just m3-12 cancel PATH` | Record a stop request and exclude new controller submissions at the next dispatch boundary. Inspect current work before further actions. |
| `just m3-12 resume PATH` | Read the original diagnostic status. Reconcile missing terminal evidence before attempting any repeat. |
| `just m3-12 finalize PATH` | Reopen or publish the summary from the same original outcome. |
| `just m3-12 cleanup PATH` | Use the existing owned-fixture cleanup protocol after a known original result. The attempt evidence remains. |

An installed failure keeps the fixture when its existing local ownership fence
allows retention. The retained debugger and guest collection require the bound
fixture and installed tooling. Live host, provider, and production adapters are
delivered with their corresponding M3.12 slices.

The public summary omits exception text, environment, arguments, and native
output. Private checkpoints also exclude these values. Ansible phase streams
are disabled on the M3.12 path. The attended shell is never transcribed by the
diagnostic launcher. Keep any later repair scripts free of exclusion-policy
content. Preserve the private attempt and its original outcome even when a
secondary collector, finalizer or cleanup action fails.

The existing installed `transport-recovery` group contains the P2 witness.
It exercises a failing root-owned helper through the real Ansible Docker
connection, a disconnected observer while systemd still runs, a setup failure
before guest setup, and a rejected export. The allowlisted
`m3-12-installed-diagnostic-proof.json` attests to these checks and to synthetic
secret exclusion from the console, private checkpoints and exported summary.
