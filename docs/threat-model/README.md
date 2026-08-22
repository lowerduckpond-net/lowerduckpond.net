# Threat models

Threat models record attacker assumptions, protected assets, trust boundaries,
security invariants, required evidence, and accepted residual risk for features
that cross a security boundary.

Accepted models:

- [Static publication](static-publication.md): Milestone 3 manifests, archives,
  immutable releases, privileged activation, Caddy routing, lifecycle, backup,
  restore, and reconciliation.

Extend or supersede the relevant model before enabling a materially different
trust boundary such as public upload, custom domains, PHP execution, tenant SQL,
or multi-host provisioning.
