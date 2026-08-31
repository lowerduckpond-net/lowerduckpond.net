# OpenTofu modules

- `digitalocean-host/` owns the VPC, administrative SSH key, Basic Droplet,
  reserved IPv4 address, assignment, and Cloud Firewall.
- `digitalocean-spaces/` owns retained Restic backup storage and its scoped
  runtime credential.
- `digitalocean-tenant-archives/` owns separately retained, non-expiring tenant
  archive storage and its independently scoped runtime credential.
- `cloudflare-public-edge/` owns one zone's apex and wildcard records, strict
  TLS mode, authenticated origin pulls, cache bypass, transform controls, and
  reserved-path policy through an explicit rollout phase.

Modules expose only the outputs their callers need and contain no provider
credentials or production-specific identifiers.
