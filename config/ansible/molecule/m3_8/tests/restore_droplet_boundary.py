"""Check that installed Docker reconstruction cannot acquire Droplet authority."""

from hashlib import sha256

from restore_fixture import Fixture, checked

from scripts.m3_12_contracts import DISPOSABLE, digest, encode
from scripts.m3_12_droplet_inventory import (
    ApprovedAllocation,
    ConnectedDroplet,
    ProviderIdentity,
    enrollment_records,
)
from scripts.qualification_mutation import protected_fixture

RUN = "00000000-0000-7000-8000-000000000098"


@protected_fixture
def require_no_droplet_authority(fixture: Fixture) -> None:
    # This case uses the existing owned MinIO fixture. Its other assertions
    # continue to exercise the real legacy fence, bootstrap, data and ingress.
    assert fixture.live_storage is None
    machine_id = str(fixture.target["destinationMachineId"])
    identity = ProviderIdentity("1" * 64, 98, "192.0.2.98")
    approved = ApprovedAllocation(
        run_id=RUN,
        role="restore",
        state_sha256="2" * 64,
        allocation_sha256="3" * 64,
        inventory_sha256="4" * 64,
        transaction_namespace_sha256="5" * 64,
        identity=identity,
    )
    observed = ConnectedDroplet(
        provider=identity,
        metadata_id=identity.droplet_id,
        metadata_ipv4=identity.ipv4,
        host_identity={
            "machineSha256": sha256(machine_id.encode("ascii")).hexdigest(),
            "systemUuidSha256": "6" * 64,
            "hostKeySha256": "7" * 64,
        },
        pinned_host_key_sha256="7" * 64,
    )
    exclusions = {
        "format": "lowerduckpond-m3-12-droplet-production-exclusions-v1",
        "dropletIds": [99],
        "addresses": ["192.0.2.99"],
        "identityDigests": ["8" * 64],
    }
    target, enrollment = enrollment_records(approved, observed, encode(exclusions))
    assert target["targetKind"] == DISPOSABLE
    policy = {
        **fixture.target,
        "launch": None,
        "publicationEnabled": False,
        "dropletRestore": {
            "format": "lowerduckpond-m3-12-droplet-restore-scope-v1",
            "runId": RUN,
            "sourceTargetSha256": "9" * 64,
            "destinationTargetSha256": digest(target),
            "sourceLaunchReceiptSha256": None,
        },
    }
    payload = {
        "droplet-target.json": target,
        "droplet-enrollment.json": enrollment,
        "droplet-production-exclusions.json": exclusions,
    }
    result = checked(
        fixture.destination,
        f"""
import os, subprocess, sys, tempfile
from pathlib import Path
assert os.geteuid() == 0 and Path("/.dockerenv").is_file()
install = Path("/opt/lowerduckpond/static-host-agent")
artifact = install / {fixture.target["originalArtifactSha256"]!r}
assert (install / "current").resolve(strict=True) == artifact
subprocess.run(
    ["/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact", str(artifact)],
    check=True,
)
sys.dont_write_bytecode = True
sys.path.insert(0, str(artifact / "site-packages"))
from lowerduckpond_static_host_agent.host_restore_delivery import (
    delivery_readback, publication_files,
)
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from scripts.m3_12_contracts import ValidationError, encode
policy = RestoreInputs.from_bytes(encode({policy!r}))
assert Path("/etc/machine-id").read_text().strip() == policy.document["destinationMachineId"]
with tempfile.TemporaryDirectory(prefix="ldp-rejected-droplet-") as scratch:
    authority = Path(scratch) / "droplet-publication"
    authority.mkdir(mode=0o700)
    for name, document in {payload!r}.items():
        entry = authority / name
        entry.write_bytes(encode(document))
        entry.chmod(0o600)
    files = publication_files(authority, policy, owner=0)
    assert set(files) == set({tuple(payload)!r})
    try:
        delivery_readback(policy, artifact.name, owner=0, authority=authority)
    except ValidationError as error:
        assert str(error) == "droplet-enrollment-conflicts"
    else:
        raise AssertionError("installed Docker destination accepted Droplet authority")
print("installed Docker rejected copied Droplet delivery")
""",
    )
    assert result.strip() == "installed Docker rejected copied Droplet delivery"
