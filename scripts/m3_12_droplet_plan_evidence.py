"""Bind the original encrypted plan to reviewed source, inputs and readback."""

from __future__ import annotations

import base64
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from lowerduckpond_static_contracts import decode_json_object

from scripts.m3_12_contracts import MAX_RECORD_BYTES, digest, require
from scripts.m3_12_droplet_plan import ApprovedHostPlan, verify_initial_host_plan

ROOT = Path("infra/opentofu/environments/m3-12-qualification")
INPUTS = str(ROOT / "reviewed.tfvars.json")
OFFLINE_FILES = frozenset(
    {
        "infra/opentofu/modules/digitalocean-host/cloud-init.yaml.tftpl",
        INPUTS,
        *(
            str(ROOT / name)
            for name in (
                ".terraform.lock.hcl",
                "main.tf",
                "outputs.tf",
                "providers.tf",
                "variables.tf",
                "versions.tf",
            )
        ),
    }
)
BACKEND_FILES = frozenset({str(ROOT / "backend.tf"), str(ROOT / "reviewed-backend.hcl")})
PLAN_VARIABLES = frozenset(
    {
        "qualification_run_id",
        "fixture_role",
        "digitalocean_project_id",
        "admin_ssh_key_fingerprint",
        "admin_ssh_public_key",
        "admin_source_cidrs",
    }
)


def configuration_digest(files: Mapping[str, bytes]) -> str:
    require(
        files.keys() in (OFFLINE_FILES, OFFLINE_FILES | BACKEND_FILES),
        "droplet-plan-producing-files-changed",
    )
    require(
        decode_json_object(files[INPUTS], maximum_bytes=MAX_RECORD_BYTES).keys() == PLAN_VARIABLES,
        "droplet-plan-producing-inputs-changed",
    )
    return digest({name: sha256(raw).hexdigest() for name, raw in files.items()})


@dataclass(frozen=True)
class InitialPlanEvidence:
    """Originals read by the trusted planner after generation and exact decode."""

    configuration: Mapping[str, bytes] = field(repr=False)
    encrypted_plan: bytes = field(repr=False)
    plan_json: bytes = field(repr=False)
    cloud_init: bytes = field(repr=False)

    @property
    def evidence_sha256(self) -> str:
        return digest(
            {
                "format": "lowerduckpond-m3-12-initial-plan-evidence-v1",
                "configurationSha256": configuration_digest(self.configuration),
                "encryptedPlanSha256": sha256(self.encrypted_plan).hexdigest(),
                "planJsonSha256": sha256(self.plan_json).hexdigest(),
                "cloudInitSha256": sha256(self.cloud_init).hexdigest(),
            }
        )


def verify_saved_initial_host_plan(
    evidence: InitialPlanEvidence,
    scope: ApprovedHostPlan,
    *,
    reviewed_configuration_sha256: str,
    reviewed_evidence_sha256: str,
) -> None:
    """Reopen the exact originals from independent review of the producing run."""
    require(
        configuration_digest(evidence.configuration) == reviewed_configuration_sha256,
        "droplet-plan-producing-configuration-changed",
    )
    require(
        evidence.evidence_sha256 == reviewed_evidence_sha256,
        "droplet-plan-original-evidence-changed",
    )
    envelope = decode_json_object(evidence.encrypted_plan, maximum_bytes=MAX_RECORD_BYTES)
    ciphertext = envelope.get("encrypted_data")
    require(
        envelope.get("encryption_version") == "v0" and type(ciphertext) is str and bool(ciphertext),
        "droplet-plan-encrypted-envelope-required",
    )
    plan = decode_json_object(evidence.plan_json, maximum_bytes=MAX_RECORD_BYTES)
    verify_initial_host_plan(plan, scope, cloud_init=evidence.cloud_init)


def _offline_command(
    tofu: Path,
    root: Path,
    environment: dict[str, str],
    *arguments: str,
    data: bytes | None = None,
    status: int = 0,
) -> bytes:
    result = subprocess.run(  # noqa: S603 - pinned tool and fixed backend-free commands
        (tofu, *arguments),
        cwd=root,
        env=environment,
        input=data,
        capture_output=True,
        check=False,
    )
    require(result.returncode == status, f"droplet-plan-offline-{arguments[0]}-failed")
    return result.stdout


def capture_offline_initial_host_plan(
    configuration: Mapping[str, bytes],
    scope: ApprovedHostPlan,
    *,
    reviewed_configuration_sha256: str,
    tofu: Path,
    plugins: Path,
) -> InitialPlanEvidence:
    """Stage reviewed bytes privately and capture an actual provider plan without a backend."""
    require(configuration.keys() == OFFLINE_FILES, "droplet-plan-offline-files-changed")
    require(tofu.is_absolute() and plugins.is_absolute(), "droplet-plan-offline-tool-paths-invalid")
    require(
        configuration_digest(configuration) == reviewed_configuration_sha256,
        "droplet-plan-producing-configuration-changed",
    )
    env = {
        "PATH": os.environ["PATH"],
        "TF_CLI_CONFIG_FILE": "/dev/null",
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
        "DIGITALOCEAN_TOKEN": "fixture-only",
        "DIGITALOCEAN_API_URL": "http://127.0.0.1:1",
        "TF_VAR_state_encryption_passphrase": "offline-fixture-plan-encryption-only",
    }
    with TemporaryDirectory(prefix="ldp-m312-plan-") as directory:
        workspace = Path(directory)
        for name, raw in configuration.items():
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        root = workspace / ROOT
        _offline_command(
            tofu,
            root,
            env,
            "init",
            "-backend=false",
            "-input=false",
            "-lockfile=readonly",
            f"-plugin-dir={plugins}",
        )
        rendered = _offline_command(
            tofu,
            root,
            env,
            "console",
            "-no-color",
            "-var-file=reviewed.tfvars.json",
            data=b"nonsensitive(base64encode(local.cloud_init))\n",
        )
        cloud_init = base64.b64decode(
            rendered.strip().removeprefix(b'"').removesuffix(b'"'), validate=True
        )
        require(
            sha256(cloud_init).hexdigest() == scope.cloud_init_sha256,
            "droplet-plan-cloud-init-render-changed",
        )
        _offline_command(
            tofu,
            root,
            env,
            "plan",
            "-input=false",
            "-detailed-exitcode",
            "-var-file=reviewed.tfvars.json",
            "-out=initial.tfplan",
            status=2,
        )
        saved = root / "initial.tfplan"
        encrypted = saved.read_bytes()
        decoded = _offline_command(tofu, root, env, "show", "-json", "initial.tfplan")
        require(saved.read_bytes() == encrypted, "droplet-plan-saved-plan-changed")
        actual = {name: (workspace / name).read_bytes() for name in configuration}
        evidence = InitialPlanEvidence(actual, encrypted, decoded, cloud_init)
        verify_saved_initial_host_plan(
            evidence,
            scope,
            reviewed_configuration_sha256=reviewed_configuration_sha256,
            reviewed_evidence_sha256=evidence.evidence_sha256,
        )
        return evidence
