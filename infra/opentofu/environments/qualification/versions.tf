terraform {
  required_version = "= 1.12.6"

  encryption {
    key_provider "pbkdf2" "state_and_plan" {
      passphrase = var.state_encryption_passphrase
    }

    method "aes_gcm" "state_and_plan" {
      keys = key_provider.pbkdf2.state_and_plan
    }

    state {
      method   = method.aes_gcm.state_and_plan
      enforced = true
    }

    plan {
      method   = method.aes_gcm.state_and_plan
      enforced = true
    }
  }

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.23.0"
    }
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "= 2.100.0"
    }
  }
}
