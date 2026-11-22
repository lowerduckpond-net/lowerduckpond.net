variable "state_encryption_passphrase" {
  description = "Client-side encryption passphrase for this disposable role's state and plan."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.state_encryption_passphrase) >= 32
    error_message = "Use a high-entropy state and plan passphrase."
  }
}

variable "qualification_run_id" {
  description = "Canonical UUIDv7 of the private M3.12 qualification run."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.qualification_run_id))
    error_message = "Use a canonical lowercase UUIDv7."
  }
}

variable "fixture_role" {
  description = "One independently allocated disposable host role."
  type        = string

  validation {
    condition     = contains(["source", "restore", "fresh"], var.fixture_role)
    error_message = "Select source, restore, or fresh."
  }
}

variable "digitalocean_project_id" {
  description = "Independently approved project ID for the disposable run."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.digitalocean_project_id))
    error_message = "Use the canonical project UUID."
  }
}

variable "admin_ssh_key_fingerprint" {
  description = "Fingerprint of the existing approved administrative public key."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{2}(:[0-9a-f]{2}){15}$", var.admin_ssh_key_fingerprint))
    error_message = "Use the DigitalOcean fingerprint of the approved public key."
  }
}

variable "admin_ssh_public_key" {
  description = "Complete OpenSSH Ed25519 public key authorized for the disposable host."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,3}( [^\\r\\n]*)?$", var.admin_ssh_public_key))
    error_message = "Use one complete Ed25519 public key without newlines."
  }
}

variable "admin_source_cidrs" {
  description = "Reviewed administrator source CIDRs for the disposable SSH listener."
  type        = set(string)
  sensitive   = true

  validation {
    condition = length(var.admin_source_cidrs) > 0 && alltrue([
      for address in var.admin_source_cidrs : try(can(cidrhost(address, 0)) && tonumber(split("/", address)[1]) > 0, false)
    ])
    error_message = "Specify one or more explicit administrator CIDRs without world-open access."
  }
}
