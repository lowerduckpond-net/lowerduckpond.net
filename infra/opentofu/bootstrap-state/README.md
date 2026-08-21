# State bootstrap

This root creates the private, versioned Spaces bucket and bucket-scoped key
used by the production OpenTofu S3 backend. It deliberately uses local state
because a backend cannot create itself.

Run it once from a trusted operator workstation using the procedure in
[`docs/operations/infrastructure.md`](../../../docs/operations/infrastructure.md).
Its local state and saved plans are encrypted by OpenTofu, but the passphrase is
still required for recovery. Keep the encrypted state and passphrase in
separate operator custody; never commit either or upload state as an ordinary
CI artifact.

The state bucket is protected by `prevent_destroy`. Removing it requires a
separately reviewed code change and an explicit migration or backup of the
production state.
