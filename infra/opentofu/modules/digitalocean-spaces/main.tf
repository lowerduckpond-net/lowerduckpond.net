resource "digitalocean_spaces_bucket" "backups" {
  name          = var.bucket_name
  region        = var.region
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  lifecycle_rule {
    id      = "backups-retention"
    prefix  = "backups/"
    enabled = true

    abort_incomplete_multipart_upload_days = 7

    noncurrent_version_expiration {
      days = var.noncurrent_version_retention_days
    }
  }

  lifecycle_rule {
    id      = "archives-retention"
    prefix  = "archives/"
    enabled = true

    abort_incomplete_multipart_upload_days = 7

    expiration {
      days = var.archive_retention_days
    }

    noncurrent_version_expiration {
      days = var.noncurrent_version_retention_days
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_spaces_key" "runtime" {
  name = var.runtime_key_name

  grant {
    bucket     = digitalocean_spaces_bucket.backups.name
    permission = "readwrite"
  }
}
