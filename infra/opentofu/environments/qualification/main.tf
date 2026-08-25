locals {
  cloudflare_networks = jsondecode(file("${path.root}/../../../../platform/cloudflare-networks.json"))
  cloudflare_proxy_cidrs = concat(
    local.cloudflare_networks.cloudflare_ipv4_cidrs,
    local.cloudflare_networks.cloudflare_ipv6_cidrs,
  )
  edge_zones = {
    lowerduckpond_net = {
      zone_id   = var.lowerduckpond_net_zone_id
      hostnames = ["m3-qualification.lowerduckpond.net"]
    }
    lowerduckpond_com = {
      zone_id = var.lowerduckpond_com_zone_id
      hostnames = [
        "m3-a.lowerduckpond.com",
        "m3-unknown.lowerduckpond.com",
        "t-0198d17f6f4a70008000000000000001.lowerduckpond.com",
      ]
    }
  }
  dns_records = merge([
    for zone_key, zone in local.edge_zones : {
      for hostname in zone.hostnames : hostname => {
        zone_key = zone_key
        zone_id  = zone.zone_id
      }
    }
  ]...)
  edge_zone_expressions = {
    for zone_key, zone in local.edge_zones : zone_key => format(
      "http.host in {%s}",
      join(" ", [for hostname in zone.hostnames : format("\"%s\"", hostname)]),
    )
  }
  origin_pull_certificate_ids = var.origin_pull_certificate_ids[var.origin_pull_generation]
}

resource "digitalocean_droplet" "qualification" {
  name   = "lowerduckpond-m3-qualification"
  region = var.digitalocean_region
  image  = var.droplet_image
  size   = var.droplet_size

  monitoring        = false
  backups           = false
  ipv6              = false
  resize_disk       = false
  graceful_shutdown = true
  ssh_keys          = [var.admin_ssh_key_fingerprint]

  user_data = <<-CLOUD_CONFIG
    #cloud-config
    users:
      - default
      - name: ldp-admin
        groups:
          - sudo
        lock_passwd: true
        shell: /bin/bash
        ssh_authorized_keys:
          - ${trimspace(var.admin_ssh_public_key)}
        sudo:
          - ALL=(ALL) NOPASSWD:ALL
    ssh_pwauth: false
    disable_root: true
  CLOUD_CONFIG
}

resource "digitalocean_firewall" "qualification" {
  name        = "lowerduckpond-m3-qualification"
  droplet_ids = [digitalocean_droplet.qualification.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_source_cidrs
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = local.cloudflare_proxy_cidrs
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = local.cloudflare_proxy_cidrs
  }

  outbound_rule {
    protocol = "icmp"
    # Public network diagnostics are required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "53"
    # Public DNS resolution is required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "53"
    # Public DNS resolution is required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "123"
    # Public time synchronization is required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "80"
    # Ubuntu and Go dependencies may be served or redirected over HTTP.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "443"
    # Ubuntu, Go, ACME, and Cloudflare APIs require public HTTPS.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_project_resources" "qualification" {
  project   = var.digitalocean_project_id
  resources = [digitalocean_droplet.qualification.urn]
}

resource "cloudflare_dns_record" "qualification" {
  for_each = local.dns_records

  zone_id = each.value.zone_id
  name    = each.key
  content = digitalocean_droplet.qualification.ipv4_address
  type    = "A"
  ttl     = 1
  proxied = true
  comment = "Disposable Lower Duck Pond M3.0 edge qualification record"
}

resource "cloudflare_authenticated_origin_pulls" "qualification" {
  for_each = local.dns_records

  zone_id = each.value.zone_id
  config = [{
    hostname = each.key
    cert_id  = local.origin_pull_certificate_ids[each.value.zone_key]
    enabled  = true
  }]
}

resource "cloudflare_ruleset" "qualification_cache_bypass" {
  for_each = local.edge_zones

  zone_id     = each.value.zone_id
  name        = "Lower Duck Pond M3.0 qualification cache bypass"
  description = "Disposable qualification hostnames only; remove during complete teardown"
  kind        = "zone"
  phase       = "http_request_cache_settings"
  rules = [{
    action      = "set_cache_settings"
    expression  = local.edge_zone_expressions[each.key]
    description = "Never cache a Milestone 3 qualification response"
    enabled     = true
    ref         = "lowerduckpond_m3_qualification_cache_bypass"
    action_parameters = {
      cache = false
    }
  }]
}

resource "cloudflare_ruleset" "qualification_transform_disable" {
  for_each = local.edge_zones

  zone_id     = each.value.zone_id
  name        = "Lower Duck Pond M3.0 qualification transform policy"
  description = "Disposable qualification hostnames only; remove during complete teardown"
  kind        = "zone"
  phase       = "http_config_settings"
  rules = [{
    action      = "set_config"
    expression  = local.edge_zone_expressions[each.key]
    description = "Preserve origin representations for qualification"
    enabled     = true
    ref         = "lowerduckpond_m3_qualification_transform_disable"
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

resource "cloudflare_ruleset" "qualification_cdn_cgi_block" {
  for_each = local.edge_zones

  zone_id     = each.value.zone_id
  name        = "Lower Duck Pond M3.0 qualification reserved path"
  description = "Disposable qualification hostnames only; remove during complete teardown"
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  rules = [{
    action = "block"
    expression = format(
      "(%s) and (lower(http.request.uri.path) eq \"/cdn-cgi\" or starts_with(lower(http.request.uri.path), \"/cdn-cgi/\"))",
      local.edge_zone_expressions[each.key],
    )
    description = "Block Cloudflare's reserved path before it reaches Caddy"
    enabled     = true
    ref         = "lowerduckpond_m3_qualification_cdn_cgi_block"
  }]
}
