variable "digitalocean_project_id" {
  description = "UUID of the existing lowerduckpond.net DigitalOcean project."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.digitalocean_project_id))
    error_message = "digitalocean_project_id must be a lowercase UUID."
  }
}

variable "state_encryption_passphrase" {
  description = "High-entropy passphrase used for client-side state and plan encryption."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.state_encryption_passphrase) >= 32
    error_message = "state_encryption_passphrase must contain at least 32 characters."
  }
}

variable "digitalocean_region" {
  description = "DigitalOcean region for compute and networking."
  type        = string
  default     = "nyc1"
}

variable "spaces_region" {
  description = "Nearest DigitalOcean region that supports Spaces."
  type        = string
  default     = "nyc3"
}

variable "vpc_ip_range" {
  description = "Private network range for the production VPC."
  type        = string
  default     = "10.20.0.0/20"
}

variable "droplet_image" {
  description = "Ubuntu LTS image selected by ADR 0014."
  type        = string
  default     = "ubuntu-26-04-x64"
}

variable "droplet_size" {
  description = "Basic Droplet size; start small and resize CPU/RAM without enlarging disk."
  type        = string
  default     = "s-1vcpu-2gb"
}

variable "admin_username" {
  description = "Administrative automation account created by cloud-init."
  type        = string
  default     = "ldp-admin"
}

variable "admin_ssh_public_key" {
  description = "OpenSSH public key for the administrative automation account."
  type        = string
  sensitive   = true
}

variable "admin_source_cidrs" {
  description = "Explicit CIDRs allowed to reach SSH."
  type        = set(string)
  sensitive   = true
}

variable "backup_bucket_name" {
  description = "Globally unique Spaces bucket dedicated to Restic backups."
  type        = string
}

variable "archive_bucket_name" {
  description = "Globally unique Spaces bucket dedicated to tenant archives."
  type        = string

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.archive_bucket_name)) &&
      var.archive_bucket_name != var.backup_bucket_name
    )
    error_message = "archive_bucket_name must be a valid, distinct 3-63 character Spaces bucket name."
  }
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone identifier for lowerduckpond.net."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be a lowercase 32-character Cloudflare identifier."
  }
}

variable "cloudflare_tenant_zone_id" {
  description = "Cloudflare zone identifier for lowerduckpond.com."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_tenant_zone_id))
    error_message = "cloudflare_tenant_zone_id must be a lowercase 32-character Cloudflare identifier."
  }
}

variable "domain" {
  description = "Trusted platform domain."
  type        = string
  default     = "lowerduckpond.net"

  validation {
    condition     = var.domain == "lowerduckpond.net"
    error_message = "domain is fixed to lowerduckpond.net by the accepted architecture."
  }
}

variable "tenant_domain" {
  description = "Untrusted tenant domain."
  type        = string
  default     = "lowerduckpond.com"

  validation {
    condition     = var.tenant_domain == "lowerduckpond.com"
    error_message = "tenant_domain is fixed to lowerduckpond.com by the accepted architecture."
  }
}

variable "edge_rollout_phase" {
  description = "Fail-safe production edge phase: direct, proxied, or enforced."
  type        = string
  default     = "direct"

  validation {
    condition     = contains(["direct", "proxied", "enforced"], var.edge_rollout_phase)
    error_message = "edge_rollout_phase must be direct, proxied, or enforced."
  }
}

variable "cloudflare_origin_pull_certificate_id" {
  description = "Public ID of the uploaded lowerduckpond.net zone-level origin-pull leaf."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.edge_rollout_phase == "direct" ||
      (var.cloudflare_origin_pull_certificate_id != null &&
      can(regex("^[0-9a-f]{32}$", var.cloudflare_origin_pull_certificate_id)))
    )
    error_message = "proxied and enforced phases require the lowerduckpond.net certificate ID."
  }
}

variable "cloudflare_tenant_origin_pull_certificate_id" {
  description = "Public ID of the uploaded lowerduckpond.com zone-level origin-pull leaf."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.edge_rollout_phase == "direct" ||
      (var.cloudflare_tenant_origin_pull_certificate_id != null &&
      can(regex("^[0-9a-f]{32}$", var.cloudflare_tenant_origin_pull_certificate_id)))
    )
    error_message = "proxied and enforced phases require the lowerduckpond.com certificate ID."
  }
}
