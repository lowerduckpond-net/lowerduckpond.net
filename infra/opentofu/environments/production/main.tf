locals {
  resource_tags = toset([
    "environment:production",
    "managed-by:opentofu",
    "project:lowerduckpond",
  ])
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
  tags                 = local.resource_tags
}

module "storage" {
  source = "../../modules/digitalocean-spaces"

  bucket_name            = var.backup_bucket_name
  region                 = var.spaces_region
  archive_retention_days = var.archive_retention_days
  runtime_key_name       = "lowerduckpond-production-backups"
}

module "dns" {
  source = "../../modules/cloudflare-dns"

  zone_id             = var.cloudflare_zone_id
  domain              = var.domain
  origin_ipv4_address = module.host.reserved_ip_address
  proxied             = false
}

resource "digitalocean_project_resources" "production" {
  project = var.digitalocean_project_id
  resources = [
    module.host.droplet_urn,
    module.host.reserved_ip_urn,
    module.storage.bucket_urn,
  ]
}
