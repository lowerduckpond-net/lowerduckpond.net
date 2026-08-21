output "droplet_id" {
  description = "DigitalOcean identifier of the hosting node."
  value       = digitalocean_droplet.host.id
}

output "droplet_urn" {
  description = "DigitalOcean project resource URN for the hosting node."
  value       = digitalocean_droplet.host.urn
}

output "reserved_ip_address" {
  description = "Stable public IPv4 address assigned to the hosting node."
  value       = digitalocean_reserved_ip.host.ip_address
}

output "reserved_ip_urn" {
  description = "DigitalOcean project resource URN for the reserved address."
  value       = digitalocean_reserved_ip.host.urn
}

output "private_ip_address" {
  description = "Private VPC address of the hosting node."
  value       = digitalocean_droplet.host.ipv4_address_private
}

output "vpc_id" {
  description = "Identifier of the hosting VPC."
  value       = digitalocean_vpc.host.id
}

output "admin_username" {
  description = "Administrative SSH account created by cloud-init."
  value       = var.admin_username
}
