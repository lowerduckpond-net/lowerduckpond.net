# 0028: Use Cloudflare as the public web edge

- Status: accepted
- Date: 2026-08-25
- Supersedes: [ADR 0003](0003-caddy-cloudflare-dns.md)

## Context

ADR 0003 selected Caddy as the only public edge and used Cloudflare only for
authoritative DNS and ACME DNS-01. That direct-origin baseline made the first
host simple, but DNS-only records publish the reserved origin address and do
not put HTTP traffic through Cloudflare's DDoS protection, request controls,
cache, or edge telemetry.

Lower Duck Pond already delegates both owned zones to Cloudflare. The public
surface will include one platform site, a future authenticated application,
reusable aliases, and many untrusted static tenant origins on a small Droplet.
The free proxy and DDoS service can absorb traffic before that constrained
origin, but only if clients cannot bypass it by using the already-known origin
address.

Cloudflare also introduces a second HTTP implementation. It terminates visitor
TLS, can transform or challenge requests, can emit its own security cookies,
and may cache responses independently of Caddy. Treating proxy enablement as a
DNS toggle would leave origin bypass, stale tenant content, spoofed forwarding
headers, certificate modes, and lifecycle invalidation undefined.

## Decision

Use Cloudflare as the public HTTP and HTTPS edge for the platform-controlled
hostnames in `lowerduckpond.net` and the tenant namespace in
`lowerduckpond.com`. OpenTofu manages public apex and wildcard address records
as proxied records. Verification records, mail records, and any future
explicitly documented non-HTTP endpoint remain DNS-only. Administrative SSH
continues to use the reserved address and its administrative CIDR allowlist; it
is not hidden behind or authenticated by the web proxy.

Caddy remains the only application origin and the only component that maps a
hostname to platform or tenant content. Cloudflare does not become tenant
authority and receives no tenant manifest, release, lifecycle, operator, or
control-plane credential. Caddy continues to obtain publicly trusted apex and
wildcard origin certificates through ACME DNS-01. Set both zones to Full
(strict) so Cloudflare validates those certificates on the second TLS hop.
Visitor certificates are Cloudflare edge certificates; origin certificates
remain independently renewable and testable.

Lock the origin instead of relying on concealed DNS:

- the DigitalOcean and host firewalls admit ports 80 and 443 only from a
  reviewed snapshot of Cloudflare's published proxy networks;
- Caddy rejects every unknown host before routing and serves no tenant bytes on
  port 80;
- HTTPS requires an account-specific Authenticated Origin Pulls client
  certificate issued by a project-controlled CA, rather than the global
  Cloudflare certificate shared by every customer;
- Caddy trusts `CF-Connecting-IP` or another forwarding header only on a
  connection admitted from the pinned Cloudflare networks and authenticated as
  the expected origin pull; and
- CI checks the pinned network snapshot against Cloudflare's published list and
  requires a reviewed firewall update when it changes. A live plan never
  downloads an unreviewed allowlist. Range changes use an additive two-phase
  rotation: admit the new superset at both firewalls and verify it before
  removing retired ranges from either boundary.

Port 80 cannot use TLS client authentication. It therefore relies on the
Cloudflare source allowlist and strict host and route handling, and may return
only the documented HTTP-to-HTTPS redirect or generic rejection contracts.
Cloudflare must forward HTTP to Caddy rather than applying a blanket edge
redirect because reusable aliases have method, path, and query rules and a
root-generated destination.

Use a project-controlled private CA for origin-pull client certificates. Keep
the CA private key only in the trusted operator backup. Upload a replaceable
leaf certificate and its private key to Cloudflare from the trusted workstation
with a separate expiring certificate-lifecycle credential, then discard the
local leaf key after upload verification. Retain that credential only through
association, qualification teardown, or production rotation; use it to remove
the retired uploaded leaf and then revoke it. Neither the CA private key nor a
leaf private key may enter the repository, OpenTofu configuration, saved plans,
or state.

OpenTofu receives the returned non-secret certificate ID and manages only its
zone or hostname association and enforcement settings. Install only the CA
certificate at the origin, overlap old and new leaves during rotation, and
alert before expiration. Production uses zone-level certificates. Disposable
qualification uses short-lived per-hostname certificates so teardown can
remove every association without changing an apex or another production
hostname. The project CA is valid for at most five years and backed up with its
passphrase. Production leaves are valid for at most one year and rotate with at
least 60 days remaining. Qualification leaves and their upload credentials are
valid for at most seven days. A missed rotation closes public HTTPS rather than
falling back to the global shared certificate.

Rotate a project CA before it has less than one full production-leaf lifetime
remaining. Generate and back up the replacement CA independently, install a
combined old-and-new CA trust bundle at Caddy, upload and associate new leaves
signed only by the replacement CA, and verify every edge hostname. Only then
retire the old Cloudflare leaves and associations; remove the old CA from Caddy
in a later convergence after proving Cloudflare no longer presents it. Each
phase preserves the preceding leaf and trust anchor as its rollback. No leaf
may expire after the CA that issued it.

Keep Cloudflare credentials separated by capability:

- Caddy's non-expiring token retains only the two-zone read and DNS-edit scope
  required for ACME;
- the OpenTofu edge token receives only the two-zone DNS, SSL-setting,
  origin-pull association, and ruleset permissions required by managed edge
  resources, but never receives an origin-pull private key;
- a temporary operator credential uploads and later retires each origin-pull
  leaf, then is revoked after qualification teardown or production rotation; and
- a future runtime cache-purge token, if approved, receives only cache-purge
  authority and is never combined with any credential above.

Preserve origin representations during Milestone 3. OpenTofu disables every
optional Cloudflare feature that can rewrite a response body or inject a
script, including Email Address Obfuscation, Rocket Loader, Cloudflare Fonts,
Automatic HTTPS Rewrites, Zaraz, and Real User Monitoring. It must keep any
later equivalent feature off until an architecture review adds it to the
managed allowlist. Caddy sends `Cache-Control: no-transform` on platform and
tenant responses. Qualification compares origin and edge status, security and
redirect headers, and bodies, and proves that Cloudflare injected no script or
markup. A provider security block or challenge may replace an origin response
as an explicit availability/security event; it is not tenant content and may
not be cached as one.

Reserve Cloudflare's `/cdn-cgi/` path namespace. A managed zone WAF rule blocks
`/cdn-cgi` and every descendant on public platform, alias, and tenant hostnames;
the archive validator rejects `cdn-cgi` as a normalized, ASCII-case-insensitive
first path component so a tenant cannot publish unreachable or provider-owned
URLs. Because Cloudflare owns this endpoint and the Free plan cannot customize
its block response, that provider block is an explicit exception to Caddy's
generic `404` contract and must never reach Caddy. M3.0 must prove the WAF rule
preempts Cloudflare's diagnostic endpoints; if it cannot, the edge design
requires review rather than silently accepting `/cdn-cgi/trace`.

Cloudflare caching is fail-closed during Milestone 3. Explicit edge rules bypass
cache for the entire `.com` namespace and `secure.lowerduckpond.net`, while
Caddy retains `no-store` on aliases, the `.com` apex, unknown hosts, errors, and
other lifecycle-sensitive responses. The public `.net` site also begins with
cache bypass so edge adoption and cache adoption remain separate changes.
Cloudflare may emit its own security cookies, but no tenant response
`Set-Cookie` may reach the edge, no LDP application trusts a Cloudflare cookie
as authentication, and Caddy continues to remove all request cookies before
static tenant handling.

CDN caching is a later Milestone 5 feature, not an implied side effect of
proxying. Before enabling it, record and test exact cache keys, browser and edge
TTLs, stale-serving behavior, purge authority, and recovery semantics for
deploy, rollback, suspend, resume, rename, archive, restore, delete, and slug
reuse. Reusable aliases, the `.com` apex, unknown hosts, errors, and the trusted
administration application remain permanently uncacheable. A cache failure may
delay or deny an operation but may not silently report a lifecycle transition
complete while obsolete tenant bytes remain eligible at the edge.

M3.0 must qualify the actual edge before another live result can satisfy its
gate. Use proxied disposable hostnames, Full (strict), a disposable
per-hostname origin-pull certificate, Cloudflare-only web ingress, and the real
supported browsers. Prove edge and origin certificates separately, direct
origin bypass, forwarding-header authenticity, cookie and response-header
behavior, response-body fidelity, `/cdn-cgi/` denial, cache bypass across
repeated requests and lifecycle-shaped status changes, strict unknown-host
handling, and complete teardown. The exact `.com`
apex remains locally exercised on the disposable host until its reviewed
production cutover; M3.12 repeats the full edge suite against both production
apexes and wildcards before publication is enabled.

The current Cloudflare AOP documentation lists the feature on every plan tier
and describes uploaded certificates for both zone-level and per-hostname
configuration. Qualification must still call the intended account APIs before
provisioning and fail with a fixed unsupported-entitlement result if the actual
free account cannot create those resources; it may not fall back to the global
certificate shared across Cloudflare accounts.

Roll production out in fail-open-for-recovery order, without a manual orange
cloud toggle:

1. install and validate the origin-pull CA and Caddy configuration without yet
   requiring a client certificate;
2. configure Full (strict), edge cache bypass, account-specific origin pulls,
   and proxied records through reviewed OpenTofu;
3. verify edge and origin paths, then require the client certificate and narrow
   both firewalls to Cloudflare networks; and
4. retain an explicit rollback that first reopens the origin and relaxes client
   authentication before returning records to DNS-only.

## Consequences

Cloudflare can absorb and classify public attacks before they reach the small
Droplet, hide the reserved address from ordinary DNS responses, and provide a
future CDN path. That protection is incomplete until both firewall layers and
origin-pull authentication reject direct requests; the address has already
been public and must never be treated as a secret.

Cloudflare becomes part of public availability, TLS, request semantics, and
incident response. Caddy remains a security boundary even though it is now an
origin rather than the public edge. Qualification and monitoring must observe
both hops, distinguish edge failures from origin failures, and verify that
Cloudflare cannot turn an origin rejection into cached or transformed tenant
content.

The project gains a private-CA and leaf-certificate rotation duty, a mutable
Cloudflare network allowlist, additional narrowly scoped OpenTofu permissions,
and a phased recovery procedure. A DNS-only rollback intentionally sacrifices
Cloudflare protection and is an explicit incident action, not a routine
console change.

Deferring cache eligibility preserves current lifecycle semantics but means
the initial proxy rollout gains DDoS protection without material CDN offload.
Later caching requires an independent threat-model and implementation review.

## Alternatives considered

Keeping Caddy as the public edge was rejected as the desired production state
because it leaves the small origin directly exposed and wastes an already
delegated protection layer. It remains the currently deployed transitional
state until the reviewed edge rollout lands.

Proxying DNS without origin lockdown was rejected because anyone retaining the
origin address could bypass Cloudflare. Trusting only Cloudflare source IPs was
rejected as the complete HTTPS identity because those networks are shared by
other customers; account-specific origin pulls provide the additional
boundary.

Cloudflare Tunnel was deferred because it adds a connector daemon and a
different availability, routing, debugging, and credential boundary when the
existing reserved-address origin can be constrained with firewalls and mTLS.
It may be reconsidered during multi-host scaling.

Enabling cache immediately was rejected because stable tenant URLs change
meaning across deployment and lifecycle operations. A cache purge is a
privileged state transition and failure mode, not a performance toggle.

## References

- [0022: Test static publication as a security boundary](0022-test-static-publication-as-a-security-boundary.md)
- [0024: Separate trusted platform and untrusted tenant domains](0024-separate-platform-and-tenant-domains.md)
- [Cloudflare proxy status](https://developers.cloudflare.com/dns/proxy-status/)
- [Cloudflare Full (strict) mode](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/)
- [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
- [Zone-level Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/)
- [Per-hostname Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/per-hostname/)
- [Cloudflare origin protection](https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/)
- [Cloudflare cache behavior](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/)
- [Cloudflare cache purging](https://developers.cloudflare.com/cache/how-to/purge-cache/)
- [Cloudflare Email Address Obfuscation](https://developers.cloudflare.com/waf/tools/scrape-shield/email-address-obfuscation/)
- [Cloudflare configuration-rule settings](https://developers.cloudflare.com/rules/configuration-rules/settings/)
- [Cloudflare `/cdn-cgi/` endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/)
- [Cloudflare WAF custom rules](https://developers.cloudflare.com/waf/custom-rules/)
