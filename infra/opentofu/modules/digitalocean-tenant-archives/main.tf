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
  }
}

resource "digitalocean_spaces_key" "runtime" {
  name = var.runtime_key_name

  grant {
    bucket     = digitalocean_spaces_bucket.archives.name
    permission = "readwrite"
  }
}
