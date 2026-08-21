resource "digitalocean_spaces_bucket" "state" {
  name          = var.state_bucket_name
  region        = var.spaces_region
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  lifecycle_rule {
    id      = "state-version-retention"
    prefix  = ""
    enabled = true

    abort_incomplete_multipart_upload_days = 7

    noncurrent_version_expiration {
      days = 90
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_spaces_key" "state" {
  name = "lowerduckpond-opentofu-state"

  grant {
    bucket     = digitalocean_spaces_bucket.state.name
    permission = "readwrite"
  }
}
