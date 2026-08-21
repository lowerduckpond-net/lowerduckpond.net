terraform {
  required_version = "= 1.12.6"

  encryption {
    key_provider "pbkdf2" "bootstrap" {
      passphrase = var.state_encryption_passphrase
    }

    method "aes_gcm" "bootstrap" {
      keys = key_provider.pbkdf2.bootstrap
    }

    state {
      method   = method.aes_gcm.bootstrap
      enforced = true
    }

    plan {
      method   = method.aes_gcm.bootstrap
      enforced = true
    }
  }

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "= 2.100.0"
    }
  }
}
