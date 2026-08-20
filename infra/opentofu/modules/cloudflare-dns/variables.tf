variable "zone_id" {
  description = "Cloudflare zone identifier containing the managed records."
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Apex domain managed by this module."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$", var.domain))
    error_message = "domain must be a lowercase fully qualified domain name."
  }
}

variable "origin_ipv4_address" {
  description = "Reserved DigitalOcean IPv4 address used by the apex and wildcard records."
  type        = string
}

variable "proxied" {
  description = "Whether Cloudflare proxies traffic instead of returning the origin address."
  type        = bool
  default     = false
}
