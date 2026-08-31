output "apex_record_id" {
  description = "Identifier of the managed apex record."
  value       = try(cloudflare_dns_record.apex[0].id, null)
}

output "wildcard_record_id" {
  description = "Identifier of the managed wildcard record."
  value       = try(cloudflare_dns_record.wildcard[0].id, null)
}

output "rollout_phase" {
  description = "Selected fail-safe public-edge phase."
  value       = var.rollout_phase
}
