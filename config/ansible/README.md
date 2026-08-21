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
