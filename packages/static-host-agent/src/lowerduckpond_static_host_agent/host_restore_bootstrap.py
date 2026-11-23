"""Read-only workstation preflight before Ansible changes a recovery destination."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes, validate_uuid7

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_archive_helper import original_ca
from lowerduckpond_static_host_agent.host_restore_fence import require_fence_policy
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs, machine_id
from lowerduckpond_static_host_agent.host_restore_journal import MAX_RESTORE_BYTES


def verify_bootstrap_inputs(directory: Path, inputs: RestoreInputs, *, owner: int) -> int:
    """Verify the original fence and public CA against the bound recovery policy."""
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as protected:
        fence = protected.read_regular(
            (f"source-fence-{inputs.restore_id}.json",),
            expected_owner=owner,
            expected_mode=0o600,
            maximum_bytes=MAX_RESTORE_BYTES,
        )
    require_fence_policy(fence, inputs)
    return len(original_ca(inputs, root=directory, owner=owner))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--destination", type=machine_id, required=True)
    parser.add_argument("--restore-id", type=validate_uuid7, required=True)
    arguments = parser.parse_args()
    try:
        owner = os.geteuid()
        inputs = RestoreInputs.load(arguments.directory, owner=owner)
        if (
            inputs.restore_id != arguments.restore_id
            or inputs.document["destinationMachineId"] != arguments.destination
        ):
            raise ValueError("restore_bootstrap_target_mismatch")
        original_ca_count = verify_bootstrap_inputs(arguments.directory, inputs, owner=owner)
        delivery: dict[str, object] = {}
        if inputs.droplet_scope is not None:
            from lowerduckpond_static_host_agent.host_restore_delivery import (  # noqa: PLC0415
                publication_files,
            )

            delivery = {
                "activationScopeDigest": inputs.droplet_scope_digest,
                "publicationFiles": publication_files(arguments.directory, inputs, owner=owner),
            }
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "restoreId": inputs.restore_id,
                    "originalCaCount": original_ca_count,
                    "trustedInputsDigest": inputs.digest,
                    **delivery,
                }
            )
        )
        return 0
    except Exception:
        print("restore_bootstrap_inputs_unverified", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
