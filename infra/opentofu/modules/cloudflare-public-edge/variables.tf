variable "zone_id" {
  description = "Cloudflare zone identifier containing the managed public namespace."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a lowercase 32-character Cloudflare identifier."
  }
}

variable "domain" {
  description = "Apex domain managed by this public-edge instance."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$", var.domain))
    error_message = "domain must be a lowercase fully qualified domain name."
  }
}

variable "origin_ipv4_address" {
  description = "Reserved DigitalOcean IPv4 address used by the apex and wildcard records."
  type        = string

  validation {
    condition     = can(cidrnetmask("${var.origin_ipv4_address}/32"))
    error_message = "origin_ipv4_address must be an IPv4 address."
  }
}

variable "direct_records_enabled" {
  description = "Whether this zone's pre-edge apex and wildcard records already exist."
  type        = bool
}

variable "rollout_phase" {
  description = "Fail-safe public-edge phase: direct, proxied, or enforced."
  type        = string

  validation {
    condition     = contains(["direct", "proxied", "enforced"], var.rollout_phase)
    error_message = "rollout_phase must be direct, proxied, or enforced."
  }
}

variable "origin_pull_certificate_id" {
  description = "Public identifier of the already-uploaded zone-level origin-pull leaf."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.rollout_phase == "direct" ||
      (var.origin_pull_certificate_id != null &&
      can(regex("^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$", var.origin_pull_certificate_id)))
    )
    error_message = "proxied and enforced phases require a lowercase 32-hex or UUID certificate ID."
  }
}
