output "ipv4_address" {
  description = "Ephemeral public address used by Ansible and local Caddy route probes."
  value       = digitalocean_droplet.qualification.ipv4_address
}

output "qualification_identity" {
  description = "Exact disposable identity consumed by the trusted-workstation session guard."
  value = {
    droplet_id   = tostring(digitalocean_droplet.qualification.id)
    droplet_urn  = digitalocean_droplet.qualification.urn
    ipv4_address = digitalocean_droplet.qualification.ipv4_address
  }
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

output "admin_source_cidrs" {
  description = "Exact state-bound SSH sources passed to the qualification host firewall."
  value       = sort(tolist(var.admin_source_cidrs))
  sensitive   = true
}

output "origin_pull_generation" {
  description = "AOP certificate generation selected in the current disposable state."
  value       = var.origin_pull_generation
}

output "cloudflare_proxy_cidrs" {
  description = "Reviewed Cloudflare network snapshot applied to the disposable cloud firewall."
  value       = local.cloudflare_proxy_cidrs
}
