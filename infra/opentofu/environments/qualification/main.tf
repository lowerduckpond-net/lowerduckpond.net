locals {
  dns_record_names = toset([
    "m3-qualification.lowerduckpond.net",
    "m3-a.lowerduckpond.com",
    "m3-unknown.lowerduckpond.com",
    "t-0198d17f6f4a70008000000000000001.lowerduckpond.com",
  ])
}

resource "digitalocean_droplet" "qualification" {
  name   = "lowerduckpond-m3-qualification"
  region = var.digitalocean_region
  image  = var.droplet_image
  size   = var.droplet_size

  monitoring        = false
  backups           = false
  ipv6              = false
  resize_disk       = false
  graceful_shutdown = true
  ssh_keys          = [var.admin_ssh_key_fingerprint]

  user_data = <<-CLOUD_CONFIG
    #cloud-config
    users:
      - default
      - name: ldp-admin
        groups:
          - sudo
        lock_passwd: true
        shell: /bin/bash
        ssh_authorized_keys:
          - ${trimspace(var.admin_ssh_public_key)}
        sudo:
          - ALL=(ALL) NOPASSWD:ALL
    ssh_pwauth: false
    disable_root: true
  CLOUD_CONFIG
}

resource "digitalocean_firewall" "qualification" {
  name        = "lowerduckpond-m3-qualification"
  droplet_ids = [digitalocean_droplet.qualification.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_source_cidrs
  }

  inbound_rule {
    protocol   = "tcp"
    port_range = "80"
    # The disposable host must complete public ACME and browser probes.
    #trivy:ignore:DIG-0001
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol   = "tcp"
    port_range = "443"
    # The disposable host must complete public ACME and browser probes.
    #trivy:ignore:DIG-0001
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol = "icmp"
    # Public network diagnostics are required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "53"
    # Public DNS resolution is required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "53"
    # Public DNS resolution is required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "udp"
    port_range = "123"
    # Public time synchronization is required during qualification.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "80"
    # Ubuntu and Go dependencies may be served or redirected over HTTP.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol   = "tcp"
    port_range = "443"
    # Ubuntu, Go, ACME, and Cloudflare APIs require public HTTPS.
    #trivy:ignore:DIG-0003
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_project_resources" "qualification" {
  project   = var.digitalocean_project_id
  resources = [digitalocean_droplet.qualification.urn]
}

resource "cloudflare_dns_record" "qualification" {
  for_each = local.dns_record_names

  zone_id = endswith(each.value, ".lowerduckpond.net") ? var.lowerduckpond_net_zone_id : var.lowerduckpond_com_zone_id
  name    = each.key
  content = digitalocean_droplet.qualification.ipv4_address
  type    = "A"
  ttl     = 60
  proxied = false
  comment = "Disposable Lower Duck Pond M3.0 qualification record"
}
