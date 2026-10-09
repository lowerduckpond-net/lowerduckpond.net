"""Keep an existing encrypted checkpoint readable when its Connect client expires."""

from __future__ import annotations

from scripts.m3_11_unattended.connect_auth import CLAIM_PREFIX, Access, claims
from scripts.m3_11_unattended.model import LifecycleError


def credential(bootstrap: dict[str, object], access: Access) -> str:
    """The retained value is encryption material only, never an API credential.

    Current authentication still uses the separately inspected native client.
    Reading the pinned genesis and complete checkpoint chain authenticates this
    key against the existing epoch; a wrong key cannot create a replacement.
    """
    value = bootstrap.get("checkpoint_token", access.token)
    if not isinstance(value, str):
        raise LifecycleError("independent checkpoint key is unavailable")
    if "checkpoint_token" in bootstrap:
        previous = claims(value)
        if (
            previous.get("sub") != access.server_id
            or previous.get(CLAIM_PREFIX + "auuid") != access.account_id
        ):
            raise LifecycleError("retained checkpoint key belongs to another Connect identity")
    return value
