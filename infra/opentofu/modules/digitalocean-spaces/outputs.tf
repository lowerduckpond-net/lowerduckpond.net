output "bucket_name" {
  description = "Name of the backup bucket."
  value       = digitalocean_spaces_bucket.backups.name
}

output "bucket_urn" {
  description = "DigitalOcean project resource URN for the bucket."
  value       = digitalocean_spaces_bucket.backups.urn
}

output "bucket_endpoint" {
  description = "Regional Spaces endpoint hostname."
  value       = digitalocean_spaces_bucket.backups.endpoint
}

output "runtime_access_key_id" {
  description = "Bucket-scoped access key ID for the backup runtime."
  value       = digitalocean_spaces_key.runtime.access_key
  sensitive   = true
}

output "runtime_secret_access_key" {
  description = "Bucket-scoped secret key for the backup runtime."
  value       = digitalocean_spaces_key.runtime.secret_key
  sensitive   = true
}
