resource "digitalocean_spaces_bucket" "archives" {
  name          = var.bucket_name
  region        = var.region
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true

    postcondition {
      condition     = self.urn == "do:space:${self.name}"
      error_message = "The DigitalOcean provider returned an unexpected archive bucket URN."
    }
  }
}

resource "digitalocean_spaces_key" "runtime" {
  name = var.runtime_key_name

  grant {
    bucket     = digitalocean_spaces_bucket.archives.name
    permission = "readwrite"
  }
}
