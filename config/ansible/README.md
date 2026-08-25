# Reproducible host configuration

The Milestone 2 playbook composes the `base`, `firewall`, `caddy`, `podman`,
`database`, `backup`, `monitoring`, and `provisioner` roles. It targets Ubuntu
26.04 LTS and deliberately refuses another distribution release.

Run `just check-ansible` for strict linting, syntax checks, and the disposable
Molecule/Testinfra acceptance scenario. Run `just configure-production` only
from the trusted administrative network after preparing the environment and
verifying the host key as described in
[`docs/operations/host-configuration.md`](../../docs/operations/host-configuration.md).

Production credentials are read from the process environment. Production
inventory contains only the stable public name and administrative username;
credentials and administrative CIDRs must not be committed.

M3.0 adds a separate `m3-qualification.yml` playbook and
`m3_qualification` role. They are for the explicitly authorized disposable
Ubuntu host only; they replace that host's fixture Caddy service with the
descriptor-pinned dual-domain prototype and must never target production. The
runner supplies its state-bound identity to a committed qualification
inventory, whose local preflight rejects a missing or additional target before
the remote play begins. Use the exact trusted-workstation sequence in
[`docs/operations/m3-qualification.md`](../../docs/operations/m3-qualification.md).
