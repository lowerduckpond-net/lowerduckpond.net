# 0024: Use lowerduckpond.net as the tenant public suffix

- Status: accepted, contingent on upstream eligibility and acceptance
- Date: 2026-08-23

## Context

Customers must receive a reusable `<slug>.lowerduckpond.net` address. The
platform also needs an authenticated administration origin whose cookies and
same-site request boundary cannot be influenced by tenant-controlled sibling
hosts.

Moving administration to `secure.lowerduckpond.net` is not sufficient by
itself. Without a browser-recognized public-suffix boundary, a tenant host can
set a `Domain=lowerduckpond.net` cookie that is sent to sibling hosts, and
requests between those hosts remain same-site. Host-only `__Host-` cookies
protect the session cookie from direct replacement but do not turn sibling
subdomains into separate sites or make `SameSite` an effective CSRF boundary.

A separate tenant domain would provide that isolation, but it would make the
required customer address only a redirect into a visibly unrelated namespace.
The project controls the complete `lowerduckpond.net` namespace and can instead
declare that its immediate children are independently operated sites.

## Decision

Seek admission of `lowerduckpond.net` to the Private section of the Public
Suffix List (PSL) and, only after acceptance and supported-browser propagation,
use it as the pinned `tenant-origin-suffix` from ADR 0018. The public host
layout is:

- `lowerduckpond.net` is stateless and redirects permanently to
  `https://hosting.lowerduckpond.net/` without setting cookies;
- `hosting.lowerduckpond.net` is the public, unauthenticated platform website;
- `secure.lowerduckpond.net` is reserved for the future trusted administration
  UI and its same-origin API;
- `<slug>.lowerduckpond.net` is the reusable platform-controlled alias defined
  by ADR 0023; and
- `t-<tenant-uuid-without-hyphens>.lowerduckpond.net` is the immutable
  tenant-controlled content origin.

Reserve `hosting`, `secure`, `www`, and every label matching the canonical
`t-<32-lowercase-hex>` form from customer slug allocation. Keep the reserved
set versioned and root-owned. Adding a later platform hostname must fail if its
label is already allocated and requires an explicit conflict migration rather
than silently taking a tenant slug. The exact apex, `hosting`, `secure`, and
every slug alias remain platform-controlled; only an immutable UUID-derived
canonical hostname may serve tenant bytes.

Treat PSL recognition as a production security dependency, not merely a DNS
configuration. Static publication remains disabled until:

1. a candid submission satisfies the then-current Private PSL eligibility,
   registration-term, domain-owner authentication, and maintenance rules;
2. the upstream Private PSL entry is accepted;
3. supported stable Chromium, Firefox, and WebKit-derived browsers recognize
   `lowerduckpond.net` as a public suffix;
4. browser tests prove a canonical tenant origin cannot set a parent-domain
   cookie, is cross-site to `secure.lowerduckpond.net`, and is cross-site to a
   second canonical tenant origin; and
5. the existing Caddy ACME path successfully obtains and renews the apex and
   `*.lowerduckpond.net` certificates after the PSL change.

The current PSL guidelines explicitly warn that small, experimental, or
short-term projects are generally declined and that projects not serving
thousands of users are quite likely to be declined. Lower Duck Pond Hosting is
a small pre-alpha project, so acceptance is a dangerous external assumption,
not an entitlement. The submission must describe the real scale and purpose
without implying users or maturity that do not exist.

If the entry is ineligible, declined, removed, or fails to propagate to the
supported browser set, production tenant publication remains disabled. A new
ADR must select another isolation mechanism—such as immutable origins on an
existing provider-controlled public suffix or separately registered tenant
domains—before implementation may weaken the distinct-site invariant. Merely
using sibling subdomains without PSL recognition is not the fallback.

Pin `lowerduckpond.net` in the backed-up root-owned platform namespace record
before creating the first tenant. Configuration, that record, every manifest,
and independent origin derivation must agree. Changing the suffix after tenant
history exists still requires a separately designed origin migration.

The future administration service uses host-only `__Host-` session cookies,
`Secure`, `HttpOnly`, an explicit `SameSite` policy, and Origin/CSRF validation.
It does not use a parent-domain cookie. The PSL boundary is the primary sibling
and cross-tenant isolation control; cookie and request checks remain defense in
depth.

## Consequences

The required friendly customer namespace and the immutable tenant origins fit
under the existing wildcard DNS and certificate scope while becoming separate
browser sites. The public website and future trusted application also have
clear, reserved homes. The apex need not carry application state.

Publication depends on external PSL eligibility, discretionary review, and
browser update propagation, none of which has a service-level deadline. The
likely small-project objection can prevent this namespace from becoming usable
at all. Implementation can proceed behind the production publication gate, but
a real tenant cannot be onboarded until the browser matrix passes. Software
that uses an old or incomplete PSL remains a compatibility risk, so
supported-browser behavior must be tested rather than inferred from the
upstream list alone.

Listing a domain in the PSL Private section is not intended to make it an ICANN
registry-controlled name. Certificate-authority guidance recommends using only
the PSL ICANN section for wildcard registry-boundary checks, but the project
will still qualify its actual ACME implementation instead of assuming issuance.

Custom tenant domains remain compatible with this design. They will map to the
same immutable tenant identity but require a later ownership, certificate,
transfer, and browser-state policy.

## Alternatives considered

Keeping `secure.lowerduckpond.net` beside untrusted sibling hosts without a PSL
entry was rejected because it relies on every authenticated endpoint remaining
safe against a related-domain attacker. Using `sites.lowerduckpond.net` or
`sites.hosting.lowerduckpond.net` as the private suffix would isolate canonical
origins but would not satisfy the requirement that customer addresses be direct
children of `lowerduckpond.net` unless those addresses remained redirects.

A second registered tenant domain provides an independent registrable-domain
boundary without PSL propagation, but adds another name, renewal dependency,
and visible redirect target. Serving tenant content directly at reusable slug
origins was rejected by ADR 0023 because reassignment would transfer persistent
browser state from the previous tenant.

## References

- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [Public Suffix List](https://publicsuffix.org/)
- [Public Suffix List submission guidelines](https://github.com/publicsuffix/list/wiki/Guidelines)
- [RFC 6265: HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265)
- [HTML Standard: same-site](https://html.spec.whatwg.org/multipage/browsers.html#same-site)
- [CA/Browser Forum TLS Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)
