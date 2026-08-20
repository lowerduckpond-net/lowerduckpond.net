# OpenTofu modules

- `digitalocean-host/` owns the VPC, administrative SSH key, Basic Droplet,
  reserved IPv4 address, assignment, and Cloud Firewall.
- `digitalocean-spaces/` owns retained backup/archive storage and its scoped
  runtime credentials.
- `cloudflare-dns/` owns the apex and wildcard records pointing at the retained
  address.

Modules expose only the outputs their callers need and contain no provider
credentials or production-specific identifiers.
