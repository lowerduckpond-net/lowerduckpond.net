# DigitalOcean tenant archive module

Creates the private, versioned Space reserved for authoritative tenant archive
bundles and a runtime key with one `readwrite` grant to that bucket alone.

The bucket deliberately has no lifecycle rule. The pinned provider cannot
express abort-only multipart cleanup without also adding an object or version
expiration, which the archive contract forbids. Managed archive code must use
one known-length `PutObject`, prohibit multipart and high-level transfer APIs,
and explicitly account for versions, delete markers, and unexpected multipart
uploads.

`force_destroy = false` and `prevent_destroy` keep this durable storage outside
ordinary application rollback. The generated credential remains a sensitive
OpenTofu output under trusted-workstation custody until the root-owned archive
component lands in M3.10.
