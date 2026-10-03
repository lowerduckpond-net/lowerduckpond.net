"""Prepare and operate one explicitly approved detached M3.11 attempt."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import approval, setup
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.docker import (
    EVIDENCE_VOLUME,
    OWNER,
    ROOT,
    Docker,
    controller_name,
    helper_volume,
    initialize_run,
    launch,
    prepare,
    source_volume,
)
from scripts.m3_11_unattended.model import LifecycleError, Targets, digest, identity
from scripts.production_qualification_inputs import current_candidate, fingerprint, revision


def start(  # noqa: PLR0913 - all approval and host bindings are explicit
    docker: Docker, *, approved: object, config: Path, source: str, mode: str, daemon_socket: str
) -> str:
    revision(source)
    value = approval.validate(approved, mode=mode, now=datetime.now(UTC))
    prepared = fields(value["prepared"], approval.PREPARED)
    current_candidate(ROOT, source)
    configuration = Configuration.load(config)
    if (
        prepared["source_revision"] != source
        or prepared["helper_revision"] != source
        or Targets.parse(value["targets"]) != configuration.targets
        or prepared["daemon"] != docker.info()
        or value["qualification_inputs_sha256"] != fingerprint(ROOT, source)
    ):
        raise LifecycleError("approved revision, targets, helper or Docker host changed")
    # One active attempt globally, including unresolved cleanup. Never silently
    # remove or replace another controller. Local admission also serializes starts.
    names = (
        docker.command(
            "ps",
            "--all",
            "--filter",
            "label=" + OWNER + "=true",
            "--filter",
            "name=ldp-m311-controller-",
            "--format",
            "{{.Names}}",
        )
        .decode()
        .splitlines()
    )
    for name in names:
        previous = identity(str(uuid.UUID(name.removeprefix("ldp-m311-controller-"))))
        status = json.loads(operate(docker, previous, "status"))
        progress = status.get("status", {})
        if progress.get("credential_cleanup") != "verified" or progress.get("phase") != "finished":
            raise LifecycleError("an active attempt or unresolved revocation blocks new starts")
    run_id = str(uuid.uuid7())
    request = {
        "format": "lowerduckpond-m3-11-unattended-request-v1",
        "binding": {
            "managed_run_id": run_id,
            "source_revision": source,
            "helper_revision": source,
            "qualification_inputs_sha256": value["qualification_inputs_sha256"],
            "storage_target_sha256": configuration.targets.storage_digest,
            "artifact_sha256": prepared["artifact_sha256"],
        },
        "mode": mode,
        "approval_sha256": digest(value),
        "controller_image": prepared["controller_image"],
    }
    image = str(prepared["controller_image"])
    initialize_run(
        docker, image=image, request=canonical_bytes(request), run_id=run_id, config=config
    )
    launch(docker, source=source, image=image, run_id=run_id, daemon_socket=daemon_socket)
    return run_id


def operate(docker: Docker, run_id: str, action: str) -> bytes:
    identity(run_id)
    value = docker.owned(controller_name(run_id))
    config = value["Config"]
    if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict):
        raise LifecycleError("controller labels are unavailable")
    source = revision(config["Labels"].get(OWNER + ".source"))
    image = value["Image"]
    if not isinstance(image, str):
        raise LifecycleError("controller image is unavailable")
    return docker.command(
        "run",
        "--rm",
        "--network",
        "none",
        "--label",
        OWNER + "=true",
        "--mount",
        f"type=volume,source={helper_volume(source)},target=/opt/lifecycle,readonly",
        "--mount",
        f"type=volume,source={source_volume(source)},target=/work/source,readonly",
        "--mount",
        f"type=volume,source={EVIDENCE_VOLUME},target=/evidence"
        + ("" if action == "cancel" else ",readonly"),
        image,
        "uv",
        "run",
        "--no-sync",
        "--frozen",
        "python",
        "-m",
        "scripts.m3_11_unattended.evidence",
        action,
        "--directory",
        "/evidence/runs/" + run_id,
        "--source",
        "/work/source",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("setup-template")
    initialize = subparsers.add_parser("setup")
    initialize.add_argument("--manifest", type=Path, required=True)
    initialize.add_argument("--output", type=Path, required=True)
    initialize.add_argument("--service-accounts-file", type=Path)
    attest = subparsers.add_parser("attest-digitalocean")
    attest.add_argument("--token-reference", required=True)
    attest.add_argument("--expires-at", required=True)
    attest.add_argument("--role", choices=("provision", "cleanup"), required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--attest-provider-console", action="store_true", required=True)
    github = subparsers.add_parser("install-github-cleanup")
    github.add_argument("--config", type=Path, required=True)
    github.add_argument("--helper-revision", required=True)
    build = subparsers.add_parser("prepare")
    build.add_argument("revision")
    build.add_argument("--output", type=Path, required=True)
    run = subparsers.add_parser("start")
    run.add_argument("revision")
    run.add_argument("--approval", type=Path, required=True)
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--mode", choices=("rehearsal", "qualification"), required=True)
    run.add_argument("--daemon-socket", required=True)
    for name in ("status", "cancel", "evidence"):
        selected = subparsers.add_parser(name)
        selected.add_argument("run_id")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == "setup-template":
            print(json.dumps(setup.template(), indent=2))
        elif args.action == "setup":
            setup.configure(args.manifest, args.output, token_file=args.service_accounts_file)
            print("Dedicated bootstrap configuration validated; no provider credential created.")
        elif args.action == "attest-digitalocean":
            setup.attest_digitalocean(
                reference=args.token_reference,
                expires=args.expires_at,
                provisioning=args.role == "provision",
                output=args.output,
            )
            print("Bound metadata written privately; import it into the dedicated metadata item.")
        elif args.action == "install-github-cleanup":
            setup.install_github(args.config, args.helper_revision)
            print(
                "Protected main-only cleanup environment configured; verify its workflow execution."
            )
        elif args.action == "prepare":
            write_private(args.output, prepare(Docker(), revision(args.revision)))
            print("Clean committed controller and qualification artifact prepared.")
        elif args.action == "start":
            print(
                start(
                    Docker(),
                    approved=read_private(args.approval),
                    config=args.config,
                    source=args.revision,
                    mode=args.mode,
                    daemon_socket=args.daemon_socket,
                )
            )
        else:
            print(operate(Docker(), args.run_id, args.action).decode(), end="")
    except RuntimeError, OSError, ValueError, TypeError, KeyError:
        parser.exit(
            1,
            "Operation incomplete; preserve private volumes and reconcile credentials.\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
