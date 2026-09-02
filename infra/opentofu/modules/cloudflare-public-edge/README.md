# Cloudflare public edge module

This module owns one complete Lower Duck Pond public zone: apex and wildcard A
records, Full (strict), Always Online and Always Use HTTPS disabled, zone-level
authenticated origin pulls, cache bypass, representation-preserving settings, and the reserved
`/cdn-cgi/` WAF defense. Cloudflare may serve exact internal endpoints before
custom rules; those endpoints remain provider-owned, unpublishable, and
isolated from Caddy.

`rollout_phase` makes the fail-safe sequence explicit:

- `direct` retains only records explicitly declared as pre-existing and creates
  no edge policy;
- `proxied` enables the reviewed edge while origin firewalls remain open; and
- `enforced` retains that edge policy while the caller narrows origin ingress.

The origin-pull certificate is uploaded separately with an expiring operator
credential. Only its nonsecret Cloudflare ID enters OpenTofu. The module reads
that public certificate and refuses to enable authenticated origin pulls unless
it is the newest active zone leaf, which is the leaf Cloudflare presents for
every proxied hostname in the zone. Cloudflare's public leaf and metadata may
therefore enter encrypted state; its private key never enters configuration,
plans, or state.
