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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--destination", type=machine_id, required=True)
    parser.add_argument("--restore-id", type=validate_uuid7, required=True)
    arguments = parser.parse_args()
    try:
        inputs = RestoreInputs.load(arguments.directory, owner=os.geteuid())
        if (
            inputs.restore_id != arguments.restore_id
            or inputs.document["destinationMachineId"] != arguments.destination
        ):
            raise ValueError("restore_bootstrap_target_mismatch")
        with DurableDirectory.open(
            arguments.directory, expected_owner=os.geteuid(), expected_directory_mode=0o700
        ) as directory:
            fence = directory.read_regular(
                (f"source-fence-{inputs.restore_id}.json",),
                expected_owner=os.geteuid(),
                expected_mode=0o600,
                maximum_bytes=MAX_RESTORE_BYTES,
            )
        require_fence_policy(fence, inputs)
        certificates = original_ca(inputs, root=arguments.directory, owner=os.geteuid())
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "restoreId": inputs.restore_id,
                    "originalCaCount": len(certificates),
                    "trustedInputsDigest": inputs.digest,
                }
            )
        )
        return 0
    except Exception:
        print("restore_bootstrap_inputs_unverified", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
