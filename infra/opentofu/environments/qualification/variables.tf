variable "state_encryption_passphrase" {
  description = "High-entropy passphrase used for client-side qualification state and plan encryption."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.state_encryption_passphrase) >= 32
    error_message = "state_encryption_passphrase must contain at least 32 characters."
  }
}

variable "digitalocean_project_id" {
  description = "UUID of the existing lowerduckpond.net DigitalOcean project."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.digitalocean_project_id))
    error_message = "digitalocean_project_id must be a lowercase UUID."
  }
}

variable "admin_ssh_key_fingerprint" {
  description = "Fingerprint of the existing lowerduckpond.net administrative SSH key in DigitalOcean."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{2}(:[0-9a-f]{2}){15}$", var.admin_ssh_key_fingerprint))
    error_message = "admin_ssh_key_fingerprint must be a lowercase MD5-style DigitalOcean fingerprint."
  }
}

variable "admin_ssh_public_key" {
  description = "OpenSSH public key installed for the disposable ldp-admin account."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,3}( .*)?$", trimspace(var.admin_ssh_public_key)))
    error_message = "admin_ssh_public_key must be one complete Ed25519 OpenSSH public key."
  }
}

variable "admin_source_cidrs" {
  description = "Explicit CIDRs allowed to reach qualification SSH."
  type        = set(string)
  sensitive   = true

  validation {
    condition = (
      length(var.admin_source_cidrs) > 0 &&
      !contains(var.admin_source_cidrs, "0.0.0.0/0") &&
      !contains(var.admin_source_cidrs, "::/0")
    )
    error_message = "admin_source_cidrs must be nonempty and cannot contain a world-open CIDR."
  }
}

variable "lowerduckpond_net_zone_id" {
  description = "Cloudflare zone ID for lowerduckpond.net."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.lowerduckpond_net_zone_id))
    error_message = "lowerduckpond_net_zone_id must be a lowercase 32-character ID."
  }
}

variable "lowerduckpond_com_zone_id" {
  description = "Cloudflare zone ID for lowerduckpond.com."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.lowerduckpond_com_zone_id))
    error_message = "lowerduckpond_com_zone_id must be a lowercase 32-character ID."
  }
}

variable "origin_pull_certificate_ids" {
  description = "Non-secret uploaded per-hostname AOP certificate IDs for both rollover generations and zones."
  type = object({
    primary = object({
      lowerduckpond_net = string
      lowerduckpond_com = string
    })
    replacement = object({
      lowerduckpond_net = string
      lowerduckpond_com = string
    })
  })

  validation {
    condition = alltrue(flatten([
      for generation in [var.origin_pull_certificate_ids.primary, var.origin_pull_certificate_ids.replacement] : [
        for certificate_id in values(generation) : can(regex("^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$", certificate_id))
      ]
    ]))
    error_message = "Every origin-pull certificate ID must use Cloudflare's lowercase 32-hex or UUID form."
  }
}

variable "origin_pull_generation" {
  description = "Uploaded AOP leaf generation selected for every disposable hostname."
  type        = string
  default     = "primary"

  validation {
    condition     = contains(["primary", "replacement"], var.origin_pull_generation)
    error_message = "origin_pull_generation must be primary or replacement."
  }
}

variable "digitalocean_region" {
  description = "DigitalOcean region for the disposable qualification host."
  type        = string
  default     = "nyc1"
}

variable "droplet_image" {
  description = "Production-equivalent Ubuntu image."
  type        = string
  default     = "ubuntu-26-04-x64"
}

variable "droplet_size" {
  description = "Disposable size with enough memory to build the pinned Caddy binary."
  type        = string
  default     = "s-1vcpu-2gb"
}
