mock_provider "digitalocean" {
  mock_resource "digitalocean_droplet" {
    defaults = {
      id           = "101"
      urn          = "do:droplet:101"
      ipv4_address = "192.0.2.22"
    }
  }
}

variables {
  state_encryption_passphrase = "ci-only-dummy-encryption-passphrase"
  qualification_run_id        = "00000000-0000-7000-8000-000000000001"
  fixture_role                = "restore"
  digitalocean_project_id     = "00000000-0000-4000-8000-000000000002"
  admin_ssh_key_fingerprint   = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
  admin_ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
  admin_source_cidrs          = ["192.0.2.14/32"]
}

run "cold_restore_is_private" {
  command = plan

  assert {
    condition = (
      digitalocean_droplet.fixture.name == "ldp-m312-00000000000070008000000000000001-restore" &&
      digitalocean_droplet.fixture.image == "ubuntu-26-04-x64" &&
      digitalocean_droplet.fixture.size == "s-2vcpu-4gb-amd" &&
      digitalocean_droplet.fixture.region == "nyc1" &&
      !digitalocean_droplet.fixture.backups &&
      !digitalocean_droplet.fixture.ipv6 &&
      !digitalocean_droplet.fixture.resize_disk
    )
    error_message = "The cold restore host must have its own run-qualified, supported allocation."
  }

  assert {
    condition = (
      length(digitalocean_firewall.fixture.inbound_rule) == 1 &&
      one(digitalocean_firewall.fixture.inbound_rule).protocol == "tcp" &&
      one(digitalocean_firewall.fixture.inbound_rule).port_range == "22" &&
      sort(one(digitalocean_firewall.fixture.inbound_rule).source_addresses) == sort(tolist(var.admin_source_cidrs))
    )
    error_message = "Cold restore begins with only scoped administrative SSH ingress."
  }
}

run "source_uses_a_distinct_name" {
  command = plan

  variables {
    fixture_role = "source"
  }

  assert {
    condition     = digitalocean_droplet.fixture.name == "ldp-m312-00000000000070008000000000000001-source"
    error_message = "The source identity must be distinct from the restore role."
  }
}

run "foreign_role_is_rejected" {
  command = plan

  variables {
    fixture_role = "production"
  }

  expect_failures = [var.fixture_role]
}

run "world_open_admin_source_is_rejected" {
  command = plan

  variables {
    admin_source_cidrs = ["0.0.0.0/0"]
  }

  expect_failures = [var.admin_source_cidrs]
}

run "zero_prefix_with_leading_zero_is_rejected" {
  command = plan

  variables {
    admin_source_cidrs = ["0.0.0.0/00"]
  }

  expect_failures = [var.admin_source_cidrs]
}
