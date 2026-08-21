variable "state_bucket_name" {
  description = "Globally unique name of the OpenTofu state bucket."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be a valid 3-63 character Spaces bucket name."
  }
}

variable "state_encryption_passphrase" {
  description = "High-entropy passphrase used for client-side bootstrap state and plan encryption."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.state_encryption_passphrase) >= 32
    error_message = "state_encryption_passphrase must contain at least 32 characters."
  }
}

variable "spaces_region" {
  description = "DigitalOcean Spaces region used for state."
  type        = string
  default     = "nyc3"
}
