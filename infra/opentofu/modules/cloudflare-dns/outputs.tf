output "apex_record_id" {
  description = "Identifier of the managed apex record."
  value       = cloudflare_dns_record.apex.id
}

output "wildcard_record_id" {
  description = "Identifier of the managed wildcard record."
  value       = cloudflare_dns_record.wildcard.id
}
