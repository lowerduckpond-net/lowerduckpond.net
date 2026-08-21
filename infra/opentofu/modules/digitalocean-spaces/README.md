# DigitalOcean Spaces module

Creates private, versioned backup and tenant-archive storage with separate
lifecycle rules. Current Restic repository objects are never expired by bucket
age because doing so could corrupt a repository; Restic owns backup retention
and pruning. Spaces requires HTTPS, and the runtime key is limited to
read/write access on this bucket instead of receiving account-wide access.

Spaces does not provide a general bucket-level encryption switch. Backup tools
must encrypt payloads before upload; the planned Restic repository provides
that boundary. The bucket and its current contents are protected from ordinary
stack destruction by `force_destroy = false` and a `prevent_destroy` lifecycle
guard.
