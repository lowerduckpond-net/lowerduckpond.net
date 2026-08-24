# 0024: Separate trusted platform and untrusted tenant domains

- Status: accepted
- Date: 2026-08-23

## Context

Lower Duck Pond Hosting needs authenticated platform services and
tenant-controlled static sites. Browsers allow a child of a registrable domain
to set a parent-domain cookie, so serving both trust classes below
`lowerduckpond.net` would let tenant JavaScript influence cookies sent to the
future control plane. Host-only `__Host-` cookies protect a correctly named
session cookie from direct replacement, but sibling hosts remain same-site and
`SameSite` is therefore not a CSRF boundary between them.

Making the tenant namespace a Private Public Suffix would also isolate tenants
from one another. Current admission guidance makes that unrealistic for a
small community service that expects dozens rather than thousands of users.
The design must not depend on applying for, receiving, retaining, or waiting
for a Public Suffix List entry.

The project owns both `lowerduckpond.net` and `lowerduckpond.com`. Using the
second registrable domain for untrusted content creates a browser-enforced
boundary around the platform without relying on an external registry change.
It does not make sibling tenants below `.com` separate sites, so that remaining
limitation must be explicit rather than described as solved.

## Decision

Use `lowerduckpond.net` only for platform-controlled services and
`lowerduckpond.com` only for the tenant-content namespace during Milestone 3.
The initial layout is:

- `lowerduckpond.net` is the canonical public, unauthenticated platform
  website and is served directly as platform-owned content, not through the
  tenant publication contract;
- `hosting.lowerduckpond.net` and `www.lowerduckpond.net` are compatibility
  aliases that permanently redirect to the equivalent path and query at
  `https://lowerduckpond.net`;
- `secure.lowerduckpond.net` is reserved for the future authenticated UI and
  same-origin API;
- the exact `lowerduckpond.com` apex returns the generic stateless platform
  `404` with `Cache-Control: no-store` during Milestone 3;
- `<slug>.lowerduckpond.com` is the reusable platform-controlled alias from ADR
  0023; and
- `t-<tenant-uuid-without-hyphens>.lowerduckpond.com` is the immutable
  tenant-controlled static-content origin.

No tenant-controlled bytes are served from `.net`. No LDP account, operator,
control-plane, or other privileged application trusts authentication state
received on `.com`. The exact `.com` apex and every alias remain
platform-controlled and stateless. Milestone 7 designates one ordinary active
tenant as the municipal reference tenant by immutable tenant ID. After that
designation, an exact `GET` or `HEAD` for `/` without a query at the `.com`
apex receives a temporary `302` with `Cache-Control: no-store` to that tenant's
immutable `t-<tenant-uuid-without-hyphens>.lowerduckpond.com` canonical origin,
derived directly from the designated ID and pinned namespace. It never redirects
through the reusable slug alias. The apex returns the generic stateless `404` if
no tenant is designated or the designated tenant is not active, and for every
other request. Every response from the exact apex, including these fallbacks,
carries `Cache-Control: no-store`. A response already issued to an immutable
origin cannot be retargeted if the municipal tenant is renamed and its former
slug is assigned to someone else before the browser follows the redirect. The
municipal tenant otherwise uses the same manifest, friendly slug, immutable
origin, deployment, lifecycle, and slug-reuse contract as every resident
tenant.

Milestone 7 acceptance must issue the apex response, then rename the municipal
tenant and assign its former slug to another tenant before following the saved
`Location`. Navigation must still reach the designated immutable origin or a
generic unavailable response, never the replacement tenant. It must also prove
every nonqualifying apex request and every absent or inactive designation
returns the generic non-cacheable fallback. These tests are not part of the
Milestone 3 gate, which retains the apex `404`.

Reserve `hosting`, `secure`, `www`, and every label matching the canonical
`t-<32-lowercase-hex>` form from customer slug allocation. Keep the reserved
set versioned and root-owned. Adding another platform hostname must fail if its
label is allocated and requires an explicit migration rather than silently
taking a tenant slug.

Pin `lowerduckpond.com` as both the alias and tenant-origin suffix in the
backed-up root-owned platform namespace record before creating the first
tenant. Configuration, that record, every manifest, and independent origin
derivation must agree. Changing either suffix after tenant history exists
requires a separately designed origin migration.

Treat every `.com` tenant host as untrusted and every `.com` tenant-to-tenant
request as same-site but cross-origin. For Milestone 3 static routes, Caddy:

- removes every `Cookie` request header before a tenant-content handler;
- removes every `Set-Cookie` response header from tenant, alias, unknown-host,
  and `.com` apex responses;
- never varies tenant routing or static content by a cookie; and
- never persists raw cookie or authorization values in access logs.

These controls prevent the hosting service from consuming or emitting tenant
cookies over HTTP. They cannot intercept JavaScript's browser-local
`document.cookie` API. A tenant can therefore still create a
`Domain=lowerduckpond.com` cookie that is visible to another `.com` tenant,
consume shared browser cookie capacity, or cause client-side cookie-name
confusion. That residual risk is accepted for ordinary static hosting because
the platform trust boundary is on `.net`, static responses ignore cookies, and
origins still isolate DOM access, local storage, IndexedDB, and service
workers. Tenant applications must not treat an ordinary cookie as having
sibling-domain integrity; client-side static code that needs a host-bound
cookie name uses a case-sensitive `__Host-` name with `Secure` and `Path=/` and
no `Domain`. Server-side tenant sessions remain outside Milestone 3.

The future `.net` administration service uses a unique host-only `__Host-`
session cookie with `Secure`, `HttpOnly`, and `Path=/`, exact-Origin and CSRF
validation, no credentialed tenant CORS, and no state-changing safe-method
routes. It does not accept a parent-domain cookie or rely on `SameSite` as its
only request-forgery control.

Provision and qualify both Cloudflare zones, their apex and wildcard DNS, and
the apex and wildcard certificate paths before production publication. The
OpenTofu and Caddy tokens are limited to the two project zones and only their
required permissions. Actual stable-browser tests must prove that `.com`
content cannot set or receive a `.net` cookie and that all `.com` HTTP cookie
stripping behaves as configured. No PSL test or submission is a production
gate.

## Consequences

The platform authentication boundary no longer depends on project popularity,
PSL discretion, or browser-list propagation. A compromised or malicious tenant
cannot poison `.net` platform cookies, and `.com` and `.net` are cross-site as
well as cross-origin.

Mutually untrusted `.com` tenants do not receive complete cookie-jar isolation.
The remaining effects are confined to browsers that execute malicious tenant
content and to the untrusted `.com` namespace; they do not grant access to
another origin's DOM storage, LDP account state, host state, or database. Cookie
capacity exhaustion can still log out or deny service to a future privileged
application placed on `.com`, which is why Milestone 3 places none there.

The project must manage a second Cloudflare zone, two more DNS records, another
apex certificate, another wildcard certificate, and replacement infrastructure
and Caddy tokens scoped to both zones. The `.com` suffix becomes authoritative
tenant identity state and cannot later return to vanity/custom-domain use
without an explicit origin migration.

Dynamic tenants and authenticated tenant applications below `.com` cannot
inherit the static-cookie decision automatically. Each must
define how server-side cookies, CSRF, cookie capacity, and response-header
policy work before activation. Custom tenant domains remain compatible but
need later ownership, certificate, transfer, and browser-state rules.

## Alternatives considered

Private PSL admission was rejected as a launch dependency because the service
is unlikely to meet the scale expected by current admission guidance. It may be
reconsidered opportunistically later, but no contract or production gate may
assume it happens.

Keeping untrusted content below `.net` was rejected because it leaves every
future platform endpoint adjacent to a related-domain attacker. A CSP sandbox
without `allow-same-origin` would block tenant cookie and local-storage access,
but it would also break ordinary static-site modules, fetch behavior, workers,
storage, and other expected functionality. Disabling JavaScript has the same
product-level incompatibility.

Using `lowerduckpond.com` as one vanity custom domain while tenants remain on
`.net` was rejected because the owned registrable domain is more valuable as a
permanent platform/data-plane boundary. Treating the `.com` split as complete
tenant-to-tenant isolation was also rejected because sibling tenants remain in
one cookie domain without a public-suffix boundary.

## References

- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [RFC 10025: Cookies: HTTP State Management Mechanism](https://auth48-transition.rfc-editor.org/authors/rfc10025.html)
- [Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/)
- [HTML Standard: same-site](https://html.spec.whatwg.org/multipage/browsers.html#same-site)
