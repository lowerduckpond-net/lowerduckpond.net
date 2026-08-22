# 0016: Model static publication as an untrusted boundary

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 accepts tenant-controlled archives and turns them into public Caddy
routes. Review of the retired Milestone 2 route publisher demonstrated that a
syntactically valid Caddy fragment could disclose Caddy's Cloudflare token or
expose local services, and that a provisioner-controlled symlink could make
Caddy serve host files. Treating archive validation or the provisioner account
as a trustworthy boundary would recreate those vulnerabilities.

## Decision

Treat uploaded archives and the unprivileged provisioner as attacker-controlled.
Trust only the narrowly scoped root activator, reviewed host configuration, and
the operator boundary. Root independently validates identifiers, archive
contents, quotas, paths, state transitions, and generated routes before any
publication.

The platform never accepts caller-generated Caddy text, never serves a
provisioner-writable tree, and never extracts an archive into a public content
tree. Milestone 3 supports only static content at a derived
`<slug>.lowerduckpond.net` hostname. Custom domains and executable content stay
outside this boundary.

The detailed assets, actors, threats, invariants, and residual risks are
maintained in the
[static-publication threat model](../threat-model/static-publication.md).

## Consequences

The privileged activator must duplicate security-critical validation rather
than trusting an unprivileged preflight result. A compromised provisioner can
request valid tenant operations and cause bounded availability impact, but it
must not gain arbitrary filesystem, Caddy, credential, or host authority.

Publication requires explicit security tests for archive traversal, links,
resource exhaustion, route injection, races, interrupted activation, backup
overlap, and cross-tenant access.

## Alternatives considered

Allowing the provisioner to write live content was rejected because validation
would not prevent later mutation or link replacement. Accepting constrained
Caddy snippets was rejected because syntax validation does not constrain
semantics. Treating the provisioner as trusted was rejected because it is the
component that processes attacker-influenced tenant jobs.

## References

- [0003: Use Caddy and Cloudflare DNS-01](0003-caddy-cloudflare-dns.md)
- [0006: Separate the control plane and provisioner](0006-separate-control-plane-provisioner.md)
- [Static-publication threat model](../threat-model/static-publication.md)
