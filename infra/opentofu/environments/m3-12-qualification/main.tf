locals {
  name = "ldp-m312-${replace(var.qualification_run_id, "-", "")}-${var.fixture_role}"

  cloud_init = templatefile("${path.module}/../../modules/digitalocean-host/cloud-init.yaml.tftpl", {
    admin_username       = "ldp-admin"
    admin_ssh_public_key = regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,3}", var.admin_ssh_public_key)
  })
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

  user_data = local.cloud_init
}

resource "digitalocean_firewall" "fixture" {
  name        = local.name
  droplet_ids = [digitalocean_droplet.fixture.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_source_cidrs
  }

  dynamic "outbound_rule" {
    for_each = var.source_fixture_egress_isolated ? [
      { protocol = "tcp", port = "80", destinations = ["169.254.169.254/32"] },
      ] : [
      { protocol = "tcp", port = "53", destinations = ["0.0.0.0/0", "::/0"] },
      { protocol = "udp", port = "53", destinations = ["0.0.0.0/0", "::/0"] },
      { protocol = "udp", port = "123", destinations = ["0.0.0.0/0", "::/0"] },
      { protocol = "tcp", port = "80", destinations = ["0.0.0.0/0", "::/0"] },
      { protocol = "tcp", port = "443", destinations = ["0.0.0.0/0", "::/0"] },
    ]
    content {
      action     = "allow"
      protocol   = outbound_rule.value.protocol
      port_range = outbound_rule.value.port
      #trivy:ignore:DIG-0003
      destination_addresses = outbound_rule.value.destinations
    }
  }
}

resource "digitalocean_project_resources" "fixture" {
  project   = var.digitalocean_project_id
  resources = [digitalocean_droplet.fixture.urn]
}
