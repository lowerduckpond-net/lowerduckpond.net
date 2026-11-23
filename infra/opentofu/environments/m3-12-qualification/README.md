# M3.12 disposable host allocation

This root describes the initial allocation of one owned role in a P4
qualification run. A source, cold restore target, and fresh-install witness
each use their own state key and run-qualified resource name. The
`backend.hcl.example` placeholders identify the per-run, per-role location.
Keep those states separate from production and the historical M3.0 root.

The plan contains one Droplet, one firewall attached only to that Droplet,
and one assignment of that Droplet to the reviewed project. Initial ingress
contains only SSH from the exact reviewed administrator CIDRs. Public HTTP
and HTTPS ingress, reserved IP assignment, DNS, Spaces, and credentials are
outside this initial plan. The existing cloud-init template receives the
approved Ed25519 public key with its optional comment removed.

The [read-only plan guard](../../../../scripts/m3_12_droplet_plan.py) compares
the initial plan with independently selected run, role, project, SSH key,
CIDRs, and cloud-init digest. It rejects existing state, foreign resources,
and substitutions in the firewall or membership relationships. Computed
attachments must resolve from the sole planned Droplet. Applying a reviewed
saved plan still requires an independently verified backend and plan digest,
provider readback, ownership and cleanup authority, and explicit authorization.
That controller integration and later edge and storage phases are separate
work.

Local verification uses the pinned OpenTofu version, a private copy, and
`tofu init -backend=false -input=false -lockfile=readonly`, followed by
`tofu validate` and `tofu test`. Tests use the mocked provider and synthetic
inputs. `just check-opentofu` also runs those mock plans.
