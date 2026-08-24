# 0023: Separate reusable slugs from immutable tenant origins

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 originally derived each tenant's content-serving hostname from its
mutable public slug. Reassigning such a slug to another tenant would also
reassign the browser origin. Service-worker registrations and browser storage
can outlive a route, certificate, tenant, or quarantine period, so the previous
tenant's client-side state could affect a later tenant at the same origin.

Permanently tombstoning every published slug would prevent that cross-tenant
handoff, but it would turn desirable human names into an ever-shrinking
security namespace. Releasing a name would then require an operator to judge
whether the previous tenant had used it enough to justify permanent retention.
Slug reprovisioning is a product requirement, so a mutable human identifier
cannot also be the tenant's browser security identity.

## Decision

Give every tenant two distinct public identifiers:

- The **canonical tenant origin** is
  `t-<tenant-uuid-without-hyphens>.<tenant-origin-suffix>`. The root activator
  generates the immutable UUIDv7 tenant ID during `create`; a caller cannot
  choose or replace it. Tenant-controlled content and headers are served only
  from this hostname. The root-owned platform namespace record pins the
  tenant-origin suffix, and the canonical manifest stores the complete derived
  origin. They must match on every mutation and reconciliation. The pinned
  suffix must be the untrusted tenant domain selected by ADR 0024 and must
  remain separate from the trusted platform domain.
- The **slug alias** is `<slug>.lowerduckpond.com`. It is a reusable,
  platform-controlled navigation handle, not a tenant origin. No uploaded
  bytes, tenant headers, tenant redirect target, or tenant JavaScript are ever
  served from it.

For an active tenant, an exact `GET` or `HEAD` for `/` with no query at the
current slug alias receives a root-generated `302` redirect to `/` at the
tenant's canonical HTTPS origin. Every response from an alias hostname,
including every generic `404`, uses `Cache-Control: no-store`. The redirect
also uses `Referrer-Policy: no-referrer`, sets no cookie, and has only a fixed
inert platform body.

This allowlist runs on the alias hostname before Caddy's general HTTP-to-HTTPS
handling. HTTPS and plain HTTP alias listeners apply the same hostname,
lifecycle, method, exact-path, and absent-query checks. A qualifying HTTP
request receives the same root-generated `302` directly to the canonical
`https://` origin; it is not upgraded through an intermediate alias URL. Other
paths, queries, methods, unknown aliases, and aliases for non-active tenants
receive the same generic platform `404` on the scheme that received them, with
no `Location` or tenant destination and with the same explicit `no-store`
policy. No HTTP redirect copies an alias path or query. Applying `no-store` to
all alias failures avoids disclosing whether a hostname is unknown or merely
inactive and prevents a negative response from surviving later deployment,
resume, restore, rename, or slug reassignment.

The alias service does not register service workers or hold authentication
state. Platform authentication remains on the separately registered
`lowerduckpond.net` domain, so its cookies cannot be sent to `.com` aliases.
Every `.com` alias response removes `Set-Cookie`, and Caddy removes incoming
`Cookie` before handling it. Alias access logs retain only a sanitized
hostname, method class, status, and timing; they discard raw paths, queries,
`Cookie`, `Authorization`, and `Referer` before persistence.

The redirect generator accepts only the root-owned slug-to-tenant mapping and
uses the manifest origin after independently rederiving it from the stored
tenant ID and pinned platform namespace. Configuration drift, a missing
namespace record, or disagreement with the manifest fails closed before route
generation. DNS aliases, reverse-proxying tenant bytes through the slug
hostname, arbitrary redirect destinations, and path or query forwarding are
prohibited because they would preserve the recyclable hostname as a security
or data-transfer boundary.

One complete Caddy runtime generation contains both route classes:

- a canonical content route from the immutable tenant hostname to the exact
  validated release; and
- a platform alias route from the current slug to the derived canonical
  hostname.

Activation, suspension, archival, restoration, deletion, rename, and
reconciliation commit both route classes under the existing publication
transaction. Suspension and archival remove both routes. Restore republishes
both for the same tenant ID. Rename changes only the alias mapping; the
canonical origin and content route remain stable. Once rename or deletion has
durably removed an alias mapping, the old slug is eligible for another tenant
without waiting for or proving browser cleanup. Milestone 4 may add a
deterministic administrative grace period, but it is product policy rather than
a security requirement.

Tenant IDs and canonical hostnames are never reassigned. The deletion audit
tombstone records the retired tenant ID for evidence, but it does not reserve
the tenant's former slugs. A restore of the same archived tenant preserves its
tenant ID and canonical origin; importing content as a new tenant creates a
new identity and origin. The pinned suffix cannot change merely because no live
tenant remains; an origin migration requires a separate future design.

The friendly alias is not a permanent content URL. Operators and the later
portal may display it for discovery, while exports and status records retain
the canonical tenant identity. A conforming cache must not retain the alias
redirect, but a stale or non-conforming client can at worst reach the old,
separate canonical origin; it cannot give the old tenant control of the new
tenant's origin.

## Consequences

Slugs can be allocated by deterministic availability and lifecycle rules
without asking whether a previous site deserves to consume a scarce name
forever. Historical audit remains complete without participating in future
slug allocation. The permanent namespace contains only non-semantic UUID-based
origins, so consuming one does not deny another tenant a desirable name.

Visitors see the canonical hostname after following a friendly alias. Deep
links use the canonical hostname because the alias intentionally redirects
only its bare root. Search, bookmarks, and origin-scoped browser storage attach
to the stable tenant identity rather than its mutable display name.

The Caddy route model and tests become slightly broader because every active
tenant has a canonical content route and a platform alias route. In return,
rename no longer changes the content origin, and slug reuse no longer requires
an origin tombstone registry, origin-state cleanup ceremony, or subjective
operator exception.

The UUID-based hostname is an identifier rather than a secret. Knowing it does
not grant access or authority. Custom domains remain a later feature with a
separate ownership-transfer and browser-state policy.

Canonical UUID hosts are separate browser origins, so a released slug cannot
transfer DOM storage or service-worker control to its next tenant. They remain
sibling sites within `lowerduckpond.com`, however, and do not receive complete
cookie-jar integrity from this decision. ADR 0024 confines that limitation to
the untrusted static namespace and keeps platform authentication on `.net`.

## Alternatives considered

Permanently tombstoning published slugs was rejected because it creates scarce
names, unbounded historical allocation state, and subjective release pressure.
A finite quarantine plus `Clear-Site-Data` was rejected because offline clients
may never receive the network response and service-worker state is persistent.
Changing DNS, certificates, IP addresses, CNAME targets, or reverse-proxy
backends was rejected because none changes the origin in the browser's URL.

Putting tenant content at a slug plus generation suffix would permit base-slug
reuse, but rename would either change the content origin or leave a stale slug
inside the canonical name. A stable UUID-derived origin keeps lifecycle and
browser identity aligned. Sandboxing all tenant pages at a shared or reusable
origin was rejected because it would break ordinary static-site navigation,
storage, workers, and compatibility while creating a much larger browser
policy surface.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [0021: Define static tenant lifecycle semantics](0021-define-static-tenant-lifecycle-semantics.md)
- [0024: Separate trusted platform and untrusted tenant domains](0024-separate-platform-and-tenant-domains.md)
- [Service Workers](https://w3c.github.io/ServiceWorker/)
- [Clear Site Data](https://w3c.github.io/webappsec-clear-site-data/)
- [Storage Standard](https://storage.spec.whatwg.org/)
- [Building Protocols with HTTP](https://httpwg.org/specs/rfc9205.html#redirection)
