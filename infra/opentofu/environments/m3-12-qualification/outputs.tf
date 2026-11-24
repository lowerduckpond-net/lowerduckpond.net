output "allocation" {
  description = "Provider identifiers to reobserve independently before creating the enrolled inventory."
  value = {
    run_id     = var.qualification_run_id
    role       = var.fixture_role
    project_id = var.digitalocean_project_id
    droplet_id = digitalocean_droplet.fixture.id
    urn        = digitalocean_droplet.fixture.urn
    ipv4       = digitalocean_droplet.fixture.ipv4_address
    firewall   = digitalocean_firewall.fixture.id
  }
}

output "cloud_init_sha256" {
  description = "SHA-256 of the same rendered bootstrap supplied to the Droplet."
  value       = nonsensitive(sha256(local.cloud_init))
}
