# Cloudflare DNS module

Creates DNS-only apex and wildcard A records that resolve directly to the
DigitalOcean reserved IPv4 address. Cloudflare proxying is intentionally a
parameter rather than an implicit default.

This is the deployed Milestone 2 transition state, not the accepted production
edge design. ADR 0028 requires a reviewed follow-up to manage proxied public
records together with Full (strict), explicit cache bypass, account-specific
Authenticated Origin Pulls, and origin-firewall policy. Do not manually toggle
these records in the Cloudflare console; doing so would expose a partially
configured edge boundary that OpenTofu cannot reproduce or safely roll back.
