locals {
  cloudflare_networks = jsondecode(file("${path.root}/../../../../platform/cloudflare-networks.json"))
  cloudflare_proxy_cidrs = toset(concat(
    local.cloudflare_networks.cloudflare_ipv4_cidrs,
    local.cloudflare_networks.cloudflare_ipv6_cidrs,
  ))
  resource_tags = toset([
    "environment:production",
    "managed-by:opentofu",
    "project:lowerduckpond",
  ])
  edge_zones = {
    lowerduckpond_net = {
      zone_id                    = var.cloudflare_zone_id
      domain                     = var.domain
      origin_pull_certificate_id = var.cloudflare_origin_pull_certificate_id
      direct_records_enabled     = true
    }
    lowerduckpond_com = {
      zone_id                    = var.cloudflare_tenant_zone_id
      domain                     = var.tenant_domain
      origin_pull_certificate_id = var.cloudflare_tenant_origin_pull_certificate_id
      direct_records_enabled     = false
    }
  }
  web_source_cidrs = (
    var.edge_rollout_phase == "enforced"
    ? local.cloudflare_proxy_cidrs
    : toset(["0.0.0.0/0", "::/0"])
  )
}

module "host" {
  source = "../../modules/digitalocean-host"

  name                 = "lowerduckpond-production-01"
  region               = var.digitalocean_region
  vpc_ip_range         = var.vpc_ip_range
  droplet_image        = var.droplet_image
  droplet_size         = var.droplet_size
  admin_username       = var.admin_username
  admin_ssh_public_key = var.admin_ssh_public_key
  admin_source_cidrs   = var.admin_source_cidrs
  web_source_cidrs     = local.web_source_cidrs
  tags                 = local.resource_tags
}

module "storage" {
  source = "../../modules/digitalocean-spaces"

  bucket_name      = var.backup_bucket_name
  region           = var.spaces_region
  runtime_key_name = "lowerduckpond-production-backups"
}

module "tenant_archives" {
  source = "../../modules/digitalocean-tenant-archives"

  bucket_name      = var.archive_bucket_name
  region           = var.spaces_region
  runtime_key_name = "lowerduckpond-production-tenant-archives"
}

module "edge" {
  for_each = local.edge_zones

  source = "../../modules/cloudflare-public-edge"

  zone_id                    = each.value.zone_id
  domain                     = each.value.domain
  origin_ipv4_address        = module.host.reserved_ip_address
  direct_records_enabled     = each.value.direct_records_enabled
  rollout_phase              = var.edge_rollout_phase
  origin_pull_certificate_id = each.value.origin_pull_certificate_id
}

moved {
  from = module.dns.cloudflare_dns_record.apex
  to   = module.edge["lowerduckpond_net"].cloudflare_dns_record.apex[0]
}

moved {
  from = module.dns.cloudflare_dns_record.wildcard
  to   = module.edge["lowerduckpond_net"].cloudflare_dns_record.wildcard[0]
}

resource "digitalocean_project_resources" "production" {
  project = var.digitalocean_project_id
  resources = [
    module.host.reserved_ip_urn,
    module.storage.bucket_urn,
    module.tenant_archives.bucket_urn,
  ]

  depends_on = [module.tenant_archives]
}

resource "digitalocean_project_resources" "host" {
  project   = var.digitalocean_project_id
  resources = [module.host.droplet_urn]

  # On the one-time migration from the combined assignment, first remove the
  # old Droplet URN from production and then add it through this resource.
  depends_on = [digitalocean_project_resources.production]
}
