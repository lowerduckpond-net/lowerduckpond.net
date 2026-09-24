from __future__ import annotations

import argparse
import os
import ssl
import uuid
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_fence import FENCE_SCHEMA, require_fence_policy
from lowerduckpond_static_host_agent.host_restore_gate import GATE_SCHEMA
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_prepare import prepare
from lowerduckpond_static_host_agent.host_restore_services import (
    ORDINARY_ACTIVATORS,
    ORDINARY_SERVICES,
    TEMPLATES,
)
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414


@pytest.mark.parametrize("fault", ["none", "secret-mode", "same-host", "private-ca", "existing"])
def test_prepare_excludes_secrets_and_refuses_changed_or_unsafe_policy(
    configuration: dict[str, object], tmp_path: Path, fault: str
) -> None:
    def write(name: str, data: bytes) -> Path:
        path = tmp_path / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    caddy = cast(dict[str, object], configuration["caddy"])
    receipt = canonical_json_bytes(
        {
            "schema": FENCE_SCHEMA,
            "restoreId": configuration["restoreId"],
            "snapshotId": configuration["snapshotId"],
            "captureId": str(uuid.uuid7()),
            "lineageId": str(uuid.uuid7()),
            "repositoryBinding": configuration["repositoryBinding"],
            "artifactDigest": {
                "algorithm": "sha256",
                "format": "lowerduckpond-static-host-agent-artifact-v1",
                "value": configuration["originalArtifactSha256"],
            },
            "sourceMachineId": configuration["sourceMachineId"],
            "sourceGateDigest": framed_digest(
                GATE_SCHEMA,
                canonical_json_bytes(
                    {
                        "schema": GATE_SCHEMA,
                        "restoreId": configuration["restoreId"],
                    }
                ),
            ),
            "maskedUnits": sorted(
                (*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES, "caddy.service")
            ),
        }
    )
    certificate = ssl.DER_cert_to_PEM_cert(b"component-only-public-der-bytes").encode()
    secret = b"CLOUDFLARE_API_TOKEN=private-fixture-value\n"
    arguments = argparse.Namespace(
        fence=write("fence", receipt),
        namespace=write("namespace", canonical_json_bytes(configuration["namespace"])),
        launch=None,
        binary=write("binary", b"pinned-workstation-binary"),
        binary_path=caddy["binaryPath"],
        environment=write("environment", secret),
        trust_bundle=write("trust-bundle", certificate),
        ca=[write("current-ca", certificate)],
        original_ca=[write("original-ca", certificate)],
        destination_id=configuration["destinationMachineId"],
        archive_region="sfo3",
        archive_bucket="owned-test-archive",
        publication_enabled=False,
        audit_rotation_enabled=False,
        output=tmp_path / "prepared",
    )
    if fault == "secret-mode":
        arguments.environment.chmod(0o644)
    elif fault == "same-host":
        arguments.destination_id = configuration["sourceMachineId"]
    elif fault == "private-ca":
        # Construct only a PEM label, without key material, for the rejection test.
        arguments.ca[0].write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----")
    elif fault == "existing":
        arguments.output.mkdir(mode=0o700)
        (arguments.output / "existing").write_bytes(b"preserve original policy")
    if fault != "none":
        with pytest.raises((ValueError, FileExistsError, HostRestoreError)):
            prepare(arguments)
        if fault == "existing":
            assert list(arguments.output.iterdir()) == [arguments.output / "existing"]
        else:
            assert not arguments.output.exists()
        return
    inputs = prepare(arguments)
    assert RestoreInputs.load(arguments.output, owner=os.geteuid()) == inputs
    require_fence_policy(receipt, inputs)
    assert arguments.output.stat().st_mode & 0o777 == 0o700  # noqa: PLR2004 - private policy directory
    for path in arguments.output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600  # noqa: PLR2004 - private policy file
        assert secret not in path.read_bytes()
    assert not inputs.document["publicationEnabled"] and not inputs.document["auditRotationEnabled"]
