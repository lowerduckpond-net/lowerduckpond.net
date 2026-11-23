locals {
  name = "ldp-m312-${replace(var.qualification_run_id, "-", "")}-${var.fixture_role}"
}

resource "digitalocean_droplet" "fixture" {
  name              = local.name
  region            = "nyc1"
  image             = "ubuntu-26-04-x64"
  size              = "s-2vcpu-4gb-amd"
  monitoring        = false
  backups           = false
  ipv6              = false
  public_networking = true
  resize_disk       = false
  graceful_shutdown = true
  ssh_keys          = [var.admin_ssh_key_fingerprint]

  user_data = templatefile("${path.module}/../../modules/digitalocean-host/cloud-init.yaml.tftpl", {
    admin_username       = "ldp-admin"
    admin_ssh_public_key = regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,3}", var.admin_ssh_public_key)
  })
}

resource "digitalocean_firewall" "fixture" {
  name        = local.name
  droplet_ids = [digitalocean_droplet.fixture.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_source_cidrs
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "53"
    # Public DNS resolution is required for the disposable host.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "53"
    # Public DNS resolution is required for the disposable host.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "123"
    # The disposable host uses ordinary time synchronization.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "80"
    # Ubuntu package bootstrap may use HTTP before HTTPS repositories are staged.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "443"
    # Ubuntu packages and later scoped qualification APIs use HTTPS.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_project_resources" "fixture" {
  project   = var.digitalocean_project_id
  resources = [digitalocean_droplet.fixture.urn]
}
