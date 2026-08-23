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
publication. Validation is not authorization: every externally requested
tenant operation must also come from an immutable root-owned job issued through
the authenticated operator boundary.

The platform never accepts caller-generated Caddy text, never serves a
provisioner-writable tree, and never extracts an archive into a public content
tree. Milestone 3 serves static content only at an immutable UUID-derived
hostname in an operator-owned tenant namespace where each tenant is a distinct
registrable domain according to supported browsers. Reusable slug hostnames
beneath `lowerduckpond.net` remain platform-only aliases that can return only a
fixed redirect to that canonical tenant origin; they never serve tenant bytes
or headers. Custom domains and executable content stay outside this boundary.

The platform namespace record, desired manifests, observed state, deployment
records, archive records, and audit history are root-owned. The provisioner may
receive bounded status from an authorized execution, but it has no directory
access to authoritative or authorization state. All state changes and audit
appends pass through authorized, validated root-owned operations.
Milestone 3 migrates the empty provisioner-owned manifest and audit directories
created by the Milestone 2 host baseline before accepting tenant state. It also
removes the provisioner's persistent writable home and job directory. The
worker receives
a hard byte- and inode-capped private ephemeral workspace; root owns intake,
job records, and activation staging. Its sudo capability accepts only a
root-generated job ID and cannot invoke the activator with caller-selected raw
operation fields. The job binds the authenticated operator, operation, target,
correlation ID, canonical request digest, artifact digest or explicit absence,
and expected authoritative source-state digest. The activator verifies those
bindings before mutation. The provisioner cannot create, modify, replace, or
cancel a job or read a tenant export payload.

The detailed assets, actors, threats, invariants, and residual risks are
maintained in the
[static-publication threat model](../threat-model/static-publication.md).

## Consequences

The privileged activator must duplicate security-critical validation rather
than trusting an unprivileged preflight result. A compromised provisioner can
delay, deny, or replay execution of an already authorized job and cause bounded
availability impact, but it cannot originate a tenant operation, change its
meaning, obtain an export, or gain arbitrary filesystem, Caddy, credential, or
host authority. It also cannot rewrite desired or observed state or erase audit
evidence.

Publication requires explicit security tests for archive traversal, links,
resource exhaustion, route injection, races, interrupted activation, backup
overlap, and cross-tenant access.

## Alternatives considered

Allowing the provisioner to write live content was rejected because validation
would not prevent later mutation or link replacement. Accepting constrained
Caddy snippets was rejected because syntax validation does not constrain
semantics. Treating the provisioner as trusted or allowing it to originate a
validated lifecycle request was rejected because it is the component that
processes attacker-influenced tenant jobs, and a chain of valid archive and
delete requests is still destructive without operator authorization.

## References

- [0003: Use Caddy and Cloudflare DNS-01](0003-caddy-cloudflare-dns.md)
- [0006: Separate the control plane and provisioner](0006-separate-control-plane-provisioner.md)
- [0020: Use a trusted-workstation static operator interface](0020-use-a-trusted-workstation-static-operator-interface.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [Static-publication threat model](../threat-model/static-publication.md)
