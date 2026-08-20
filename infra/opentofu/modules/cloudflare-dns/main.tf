resource "cloudflare_dns_record" "apex" {
  zone_id = var.zone_id
  name    = var.domain
  content = var.origin_ipv4_address
  type    = "A"
  ttl     = 300
  proxied = var.proxied
  comment = "Managed by OpenTofu for Lower Duck Pond Hosting"
}

resource "cloudflare_dns_record" "wildcard" {
  zone_id = var.zone_id
  name    = "*.${var.domain}"
  content = var.origin_ipv4_address
  type    = "A"
  ttl     = 300
  proxied = var.proxied
  comment = "Managed by OpenTofu for Lower Duck Pond Hosting"
}
