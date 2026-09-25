"""Read-only protection policy for the nonempty production backup Space."""

from __future__ import annotations

import json
import os
import sys
from typing import cast

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.check_m3_10_provider import (
    GateError,
    PolicyClient,
    _private_acl_owner,
    _require_absent_configuration,
)
from scripts.m3_10_policy_client import make_policy_client

REVIEWED_RULE: dict[str, object] = {
    "ID": "backups-retention",
    "Prefix": "backups/",
    "Status": "Enabled",
    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
    "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
}


def check(client: PolicyClient, *, bucket: str) -> None:
    _private_acl_owner(client.get_bucket_acl(Bucket=bucket))
    _require_absent_configuration(
        client.get_bucket_policy, bucket=bucket, missing_code="NoSuchBucketPolicy"
    )
    # Match the existing production module. Restic protection retains current
    # objects; this rule only retires superseded versions and unfinished uploads.
    # Any current-object expiration/transition or additional rule is forbidden.
    rules = client.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules")
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        raise GateError("backup Space lifecycle policy differs from reviewed configuration")
    rule = dict(rules[0])
    if "Prefix" not in rule and rule.get("Filter") == {"Prefix": "backups/"}:
        del rule["Filter"]
        rule["Prefix"] = "backups/"
    if json.dumps(rule, sort_keys=True) != json.dumps(REVIEWED_RULE, sort_keys=True):
        raise GateError("backup Space lifecycle policy differs from reviewed configuration")
    if client.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
        raise GateError("backup Space versioning is not enabled")


def main() -> int:
    try:
        configuration = ArchiveConfiguration(
            os.environ["SPACES_REGION"],
            os.environ["SPACES_BACKUP_BUCKET"],
            os.environ["SPACES_ACCESS_KEY_ID"],
            os.environ["SPACES_SECRET_ACCESS_KEY"],
        )
        check(cast(PolicyClient, make_policy_client(configuration)), bucket=configuration.bucket)
    except KeyError, ValueError, OSError, RuntimeError, BotoCoreError, ClientError:
        print("M3.11 backup Space protection policy could not be verified.", file=sys.stderr)
        return 1
    print("M3.11 private, versioned backup Space and reviewed retention policy verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
