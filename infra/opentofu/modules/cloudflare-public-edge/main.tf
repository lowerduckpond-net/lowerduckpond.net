locals {
  edge_enabled    = var.rollout_phase != "direct"
  records_enabled = var.direct_records_enabled || local.edge_enabled
  origin_pull_hostnames = toset([
    var.domain,
    "*.${var.domain}",
  ])
  zone_expression = format(
    "(http.host eq \"%s\" or ends_with(http.host, \".%s\"))",
    var.domain,
    var.domain,
  )
}

resource "cloudflare_dns_record" "apex" {
  count = local.records_enabled ? 1 : 0

  zone_id = var.zone_id
  name    = var.domain
  content = var.origin_ipv4_address
  type    = "A"
  ttl     = local.edge_enabled ? 1 : 300
  proxied = local.edge_enabled
  comment = "Managed by OpenTofu for Lower Duck Pond Hosting"

  depends_on = [
    cloudflare_zone_setting.ssl,
    cloudflare_zone_setting.always_online,
    cloudflare_authenticated_origin_pulls.hostname,
    cloudflare_authenticated_origin_pulls_settings.zone,
    cloudflare_ruleset.cache_bypass,
    cloudflare_ruleset.transform_disable,
    cloudflare_ruleset.cdn_cgi_block,
  ]
}

resource "cloudflare_dns_record" "wildcard" {
  count = local.records_enabled ? 1 : 0

  zone_id = var.zone_id
  name    = "*.${var.domain}"
  content = var.origin_ipv4_address
  type    = "A"
  ttl     = local.edge_enabled ? 1 : 300
  proxied = local.edge_enabled
  comment = "Managed by OpenTofu for Lower Duck Pond Hosting"

  depends_on = [
    cloudflare_zone_setting.ssl,
    cloudflare_zone_setting.always_online,
    cloudflare_authenticated_origin_pulls.hostname,
    cloudflare_authenticated_origin_pulls_settings.zone,
    cloudflare_ruleset.cache_bypass,
    cloudflare_ruleset.transform_disable,
    cloudflare_ruleset.cdn_cgi_block,
  ]
}

data "cloudflare_authenticated_origin_pulls_certificate" "selected" {
  count = local.edge_enabled ? 1 : 0

  zone_id        = var.zone_id
  certificate_id = var.origin_pull_certificate_id
}

resource "cloudflare_authenticated_origin_pulls" "hostname" {
  for_each = local.edge_enabled ? local.origin_pull_hostnames : toset([])

  zone_id = var.zone_id
  config = [{
    hostname = each.value
    cert_id  = var.origin_pull_certificate_id
    enabled  = true
  }]

  lifecycle {
    precondition {
      condition     = data.cloudflare_authenticated_origin_pulls_certificate.selected[0].status == "active"
      error_message = "The selected zone-level origin-pull certificate must already be active."
    }
  }
}

resource "cloudflare_zone_setting" "ssl" {
  count = local.edge_enabled ? 1 : 0

  zone_id    = var.zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "always_online" {
  count = local.edge_enabled ? 1 : 0

  zone_id    = var.zone_id
  setting_id = "always_online"
  value      = "off"
}

resource "cloudflare_authenticated_origin_pulls_settings" "zone" {
  count = local.edge_enabled ? 1 : 0

  zone_id = var.zone_id
  enabled = true

  depends_on = [cloudflare_authenticated_origin_pulls.hostname]

  lifecycle {
    precondition {
      condition     = data.cloudflare_authenticated_origin_pulls_certificate.selected[0].status == "active"
      error_message = "The selected zone-level origin-pull certificate must already be active."
    }
  }
}

resource "cloudflare_ruleset" "cache_bypass" {
  count = local.edge_enabled ? 1 : 0

  zone_id     = var.zone_id
  name        = "Lower Duck Pond public edge cache bypass"
  description = "Milestone 3 serves every platform and tenant response without edge caching"
  kind        = "zone"
  phase       = "http_request_cache_settings"
  rules = [{
    action      = "set_cache_settings"
    expression  = local.zone_expression
    description = "Never cache a Milestone 3 response"
    enabled     = true
    ref         = "lowerduckpond_m3_cache_bypass"
    action_parameters = {
      cache = false
    }
  }]
}

resource "cloudflare_ruleset" "transform_disable" {
  count = local.edge_enabled ? 1 : 0

  zone_id     = var.zone_id
  name        = "Lower Duck Pond public edge transform policy"
  description = "Preserve every origin representation during Milestone 3"
  kind        = "zone"
  phase       = "http_config_settings"
  rules = [{
    action      = "set_config"
    expression  = local.zone_expression
    description = "Disable optional response transforms and script injection"
    enabled     = true
    ref         = "lowerduckpond_m3_transform_disable"
    action_parameters = {
      automatic_https_rewrites = false
      disable_rum              = true
      disable_zaraz            = true
      email_obfuscation        = false
      fonts                    = false
      rocket_loader            = false
    }
  }]
}

resource "cloudflare_ruleset" "cdn_cgi_block" {
  count = local.edge_enabled ? 1 : 0

  zone_id     = var.zone_id
  name        = "Lower Duck Pond public edge reserved path"
  description = "Keep Cloudflare's reserved path outside the published namespace"
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  rules = [{
    action = "block"
    expression = format(
      "%s and (lower(http.request.uri.path) eq \"/cdn-cgi\" or starts_with(lower(http.request.uri.path), \"/cdn-cgi/\"))",
      local.zone_expression,
    )
    description = "Block Cloudflare's reserved path before it reaches Caddy"
    enabled     = true
    ref         = "lowerduckpond_m3_cdn_cgi_block"
  }]
}
