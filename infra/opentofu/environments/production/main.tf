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
