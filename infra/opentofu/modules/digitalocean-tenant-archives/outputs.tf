output "bucket_name" {
  description = "Name of the tenant archive bucket."
  value       = digitalocean_spaces_bucket.archives.name
}

output "bucket_urn" {
  description = "DigitalOcean project resource URN for the archive bucket."
  value       = "do:space:${var.bucket_name}"
}

output "bucket_endpoint" {
  description = "Regional Spaces endpoint hostname."
  value       = digitalocean_spaces_bucket.archives.endpoint
}

output "runtime_access_key_id" {
  description = "Bucket-scoped access key ID for the root-owned archive boundary."
  value       = digitalocean_spaces_key.runtime.access_key
  sensitive   = true
}

output "runtime_secret_access_key" {
  description = "Bucket-scoped secret key for the root-owned archive boundary."
  value       = digitalocean_spaces_key.runtime.secret_key
  sensitive   = true
}
