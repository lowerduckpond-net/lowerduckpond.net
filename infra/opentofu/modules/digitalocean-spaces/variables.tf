variable "bucket_name" {
  description = "Globally unique name for backup storage."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be a valid 3-63 character Spaces bucket name."
  }
}

variable "region" {
  description = "DigitalOcean Spaces region slug."
  type        = string
  default     = "nyc3"
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain superseded object versions."
  type        = number
  default     = 30

  validation {
    condition     = var.noncurrent_version_retention_days >= 7
    error_message = "noncurrent_version_retention_days must be at least 7."
  }
}

variable "runtime_key_name" {
  description = "Name for the bucket-scoped runtime Spaces access key."
  type        = string
  default     = "lowerduckpond-production-backups"
}
