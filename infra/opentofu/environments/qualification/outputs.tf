output "ipv4_address" {
  description = "Ephemeral public address used by Ansible and local Caddy route probes."
  value       = digitalocean_droplet.qualification.ipv4_address
}

output "browser_origins" {
  description = "Exact live origins accepted by the mandatory browser harness."
  value = {
    platform         = "https://m3-qualification.lowerduckpond.net"
    tenant_alias     = "https://m3-a.lowerduckpond.com"
    tenant_immutable = "https://t-0198d17f6f4a70008000000000000001.lowerduckpond.com"
    tenant_unknown   = "https://m3-unknown.lowerduckpond.com"
  }
}
