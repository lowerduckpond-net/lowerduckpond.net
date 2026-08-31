variable "name" {
  description = "Stable name for the hosting node and its supporting resources."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.name))
    error_message = "name must be a 3-63 character lowercase DigitalOcean resource name."
  }
}

variable "region" {
  description = "DigitalOcean region slug for compute and networking resources."
  type        = string
}

variable "vpc_ip_range" {
  description = "Private RFC1918 CIDR assigned to the hosting VPC."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_ip_range))
    error_message = "vpc_ip_range must be valid CIDR notation."
  }
}

variable "droplet_image" {
  description = "DigitalOcean image slug for the hosting node."
  type        = string
}

variable "droplet_size" {
  description = "DigitalOcean Basic Droplet size slug."
  type        = string

  validation {
    condition     = startswith(var.droplet_size, "s-")
    error_message = "droplet_size must be a Basic Droplet slug beginning with s-."
  }
}

variable "admin_username" {
  description = "Administrative automation account created by cloud-init."
  type        = string
  default     = "ldp-admin"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.admin_username))
    error_message = "admin_username must be a valid Linux account name."
  }
}

variable "admin_ssh_public_key" {
  description = "Public SSH key installed for the administrative automation account."
  type        = string
  sensitive   = true

  validation {
    condition = anytrue([
      for prefix in ["ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-ed25519@openssh.com "] :
      startswith(trimspace(var.admin_ssh_public_key), prefix)
    ])
    error_message = "admin_ssh_public_key must be an OpenSSH public key."
  }
}

variable "admin_source_cidrs" {
  description = "Explicit IPv4 or IPv6 CIDRs allowed to reach SSH."
  type        = set(string)
  sensitive   = true

  validation {
    condition = (
      length(var.admin_source_cidrs) > 0 &&
      alltrue([for cidr in var.admin_source_cidrs : can(cidrhost(cidr, 0))]) &&
      !contains(var.admin_source_cidrs, "0.0.0.0/0") &&
      !contains(var.admin_source_cidrs, "::/0")
    )
    error_message = "admin_source_cidrs must contain valid explicit CIDRs and may not allow the whole Internet."
  }
}

variable "web_source_cidrs" {
  description = "Explicit IPv4 and IPv6 CIDRs allowed to reach public HTTP and HTTPS."
  type        = set(string)
  default     = ["0.0.0.0/0", "::/0"]

  validation {
    condition = (
      length(var.web_source_cidrs) > 0 &&
      alltrue([for cidr in var.web_source_cidrs : can(cidrhost(cidr, 0))])
    )
    error_message = "web_source_cidrs must contain valid explicit CIDRs."
  }
}

variable "tags" {
  description = "DigitalOcean tags attached to the Droplet."
  type        = set(string)
  default     = []
}
