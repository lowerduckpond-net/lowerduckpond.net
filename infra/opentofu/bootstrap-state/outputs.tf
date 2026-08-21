output "state_bucket_name" {
  description = "Name to configure on the production S3 backend."
  value       = digitalocean_spaces_bucket.state.name
}

output "state_bucket_endpoint" {
  description = "Regional endpoint to configure on the production S3 backend."
  value       = "https://${digitalocean_spaces_bucket.state.endpoint}"
}

output "state_access_key_id" {
  description = "Bucket-scoped access key ID for the production S3 backend."
  value       = digitalocean_spaces_key.state.access_key
  sensitive   = true
}

output "state_secret_access_key" {
  description = "Bucket-scoped secret key for the production S3 backend."
  value       = digitalocean_spaces_key.state.secret_key
  sensitive   = true
}
