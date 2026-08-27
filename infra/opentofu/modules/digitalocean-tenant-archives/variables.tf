variable "bucket_name" {
  description = "Globally unique name for tenant archive storage."
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

variable "runtime_key_name" {
  description = "Name for the bucket-scoped tenant archive access key."
  type        = string
  default     = "lowerduckpond-production-tenant-archives"
}
