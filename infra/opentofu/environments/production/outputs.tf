output "reserved_ip_address" {
  description = "Stable public IPv4 address for the hosting platform."
  value       = module.host.reserved_ip_address
}

output "backup_bucket_name" {
  description = "Spaces bucket used for backups and tenant archives."
  value       = module.storage.bucket_name
}

output "backup_bucket_endpoint" {
  description = "Spaces endpoint used by backup clients."
  value       = module.storage.bucket_endpoint
}

output "backup_runtime_access_key_id" {
  description = "Bucket-scoped access key ID consumed by host configuration."
  value       = module.storage.runtime_access_key_id
  sensitive   = true
}

output "backup_runtime_secret_access_key" {
  description = "Bucket-scoped secret key consumed by host configuration."
  value       = module.storage.runtime_secret_access_key
  sensitive   = true
}

output "ansible_inventory" {
  description = "Machine-readable inventory input for the production Ansible run."
  value = {
    all = {
      hosts = {
        lowerduckpond_production_01 = {
          ansible_host = module.host.reserved_ip_address
          ansible_user = module.host.admin_username
          private_ip   = module.host.private_ip_address
        }
      }
    }
  }
}
