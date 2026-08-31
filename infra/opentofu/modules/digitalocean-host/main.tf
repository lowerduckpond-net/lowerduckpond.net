resource "digitalocean_tag" "host" {
  for_each = var.tags

  name = each.value
}

resource "digitalocean_vpc" "host" {
  name        = "${var.name}-vpc"
  region      = var.region
  ip_range    = var.vpc_ip_range
  description = "Private network for Lower Duck Pond hosting"
}

resource "digitalocean_ssh_key" "admin" {
  name       = "${var.name}-admin"
  public_key = trimspace(var.admin_ssh_public_key)
}

resource "digitalocean_droplet" "host" {
  name     = var.name
  region   = var.region
  image    = var.droplet_image
  size     = var.droplet_size
  vpc_uuid = digitalocean_vpc.host.id

  monitoring        = true
  backups           = false
  ipv6              = false
  resize_disk       = false
  graceful_shutdown = true
  ssh_keys          = [digitalocean_ssh_key.admin.fingerprint]
  tags              = [for tag in digitalocean_tag.host : tag.name]

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_username       = var.admin_username
    admin_ssh_public_key = trimspace(var.admin_ssh_public_key)
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "digitalocean_reserved_ip" "host" {
  region = var.region

  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_reserved_ip_assignment" "host" {
  ip_address = digitalocean_reserved_ip.host.ip_address
  droplet_id = digitalocean_droplet.host.id
}

resource "digitalocean_firewall" "host" {
  name        = "${var.name}-firewall"
  droplet_ids = [digitalocean_droplet.host.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_source_cidrs
  }

  inbound_rule {
    protocol   = "tcp"
    port_range = "80"
    # Direct and proxied rollout phases intentionally retain public ingress;
    # the production plan policy permits only this or the reviewed edge CIDRs.
    #trivy:ignore:DIG-0001
    source_addresses = var.web_source_cidrs
  }

  inbound_rule {
    protocol   = "tcp"
    port_range = "443"
    # Direct and proxied rollout phases intentionally retain public ingress;
    # the production plan policy permits only this or the reviewed edge CIDRs.
    #trivy:ignore:DIG-0001
    source_addresses = var.web_source_cidrs
  }

  outbound_rule {
    protocol = "icmp"
    # Network diagnostics require public ICMP egress.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "53"
    # The host must reach its configured public DNS resolvers.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "53"
    # The host must reach its configured public DNS resolvers.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "123"
    # The host must reach public NTP servers.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "80"
    # Operating-system repositories may redirect through public HTTP.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "443"
    # Updates, ACME, backups, and monitoring require public HTTPS.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
