"""Prepare and operate one explicitly approved detached M3.11 attempt."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import approval, historical_absence, setup
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import (
    CLEANUP_VOLUME,
    EVIDENCE_VOLUME,
    OWNER,
    ROOT,
    SOCKET,
    Docker,
    admission,
    controller_name,
    helper_volume,
    initialize_run,
    launch,
    prepare,
    require_current_watchdogs,
    source_volume,
    utility,
)
from scripts.m3_11_unattended.model import (
    AuthorityGeneration,
    LifecycleError,
    Targets,
    digest,
    identity,
)
from scripts.production_qualification_inputs import current_candidate, fingerprint, revision
from scripts.provider_preflight_diagnostics import StorageReadinessError


def start(  # noqa: PLR0912, PLR0913 - all approval and host bindings are explicit
    docker: Docker, *, approved: object, config: Path, source: str, mode: str, daemon_socket: str
) -> str:
    revision(source)
    value = approval.validate(approved, mode=mode, now=datetime.now(UTC))
    prepared = fields(value["prepared"], approval.PREPARED)
    current_candidate(ROOT, source)
    configuration = LeaseConfiguration.load(config)
    if (
        len(
            {
                configuration.helper_revision,
                str(prepared["helper_revision"]),
                str(prepared["source_revision"]),
                source,
            }
        )
        != 1
    ):
        raise LifecycleError(
            "runtime revision mismatch: configuration="
            + configuration.helper_revision
            + ", prepared helper="
            + str(prepared["helper_revision"])
            + ", prepared source="
            + str(prepared["source_revision"])
            + ", requested="
            + source
        )
    if (
        configuration.mode != "controller"
        or value["policy_sha256"] != configuration.approved_policy_sha256
    ):
        raise LifecycleError("attempt approval differs from the lease policy")
    if value["lease_id"] is None:
        configuration.require_issuance(now=datetime.now(UTC))
    if (
        prepared["source_revision"] != source
        or prepared["helper_revision"] != source
        or Targets.parse(value["targets"]) != configuration.targets
        or prepared["daemon"] != docker.info()
        or value["qualification_inputs_sha256"] != fingerprint(ROOT, source)
    ):
        raise LifecycleError("approved revision, targets, helper or Docker host changed")
    image = str(prepared["controller_image"])
    with admission(docker, image=image):
        # One active attempt globally, including unresolved cleanup. Never silently
        # remove or replace another controller. The daemon reservation serializes starts.
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
        reuse_manifests: set[str] = set()
        for name in names:
            previous = identity(str(uuid.UUID(name.removeprefix("ldp-m311-controller-"))))
            status = json.loads(operate(docker, previous, "status"))
            progress = status.get("status", {})
            retained = status.get("lease", {})
            if (
                value["lease_id"] is not None
                and isinstance(retained, dict)
                and retained.get("lease_id") == value["lease_id"]
                and retained.get("policy_sha256") == configuration.approved_policy_sha256
                and retained.get("use_released") is True
                and progress.get("phase") == "finished"
                and progress.get("qualification") in {"failed", "interrupted"}
            ):
                if not isinstance(retained.get("manifest_sha256"), str):
                    raise LifecycleError("released lease manifest binding is unavailable")
                reuse_manifests.add(retained["manifest_sha256"])
                continue
            if (
                progress.get("credential_cleanup") != "verified"
                or progress.get("phase") != "finished"
            ) and not historical_absence.retained_failure(
                previous, progress, status.get("binding")
            ):
                if not isinstance(status.get("binding"), dict) or retained:
                    raise LifecycleError(
                        "an active attempt or unresolved revocation blocks new starts"
                    )
                container = docker.owned(name)
                projected = utility(
                    docker,
                    prepared=prepared,
                    operation="admission",
                    daemon_socket=daemon_socket,
                    payload={
                        "configuration": configuration.document(cleanup_only=True),
                        "run_id": previous,
                        "container_id": container["Id"],
                    },
                )
                if (
                    projected.get("run_id") != previous
                    or projected.get("container_id") != container["Id"]
                    or projected.get("mapping_sha256") != configuration.migration_sha256
                    or projected.get("helper_revision") != source
                    or projected.get("binding_sha256") != digest(status["binding"])
                ):
                    raise LifecycleError(
                        "legacy admission projection differs from the original controller"
                    )
        require_current_watchdogs(docker, source=source, image=image)
        if value["lease_id"] is not None:
            # Released runtime ownership preserves archive data. It is not an
            # empty-bucket proof. Reject retained output before consuming a new
            # attempt; worker preflight/acceptance still provide actual proof.
            if len(reuse_manifests) != 1:
                raise LifecycleError("released prior controllers disagree on the retained manifest")
            reuse_manifest = reuse_manifests.pop()
            readiness = utility(
                docker,
                prepared=prepared,
                operation="storage-admission",
                daemon_socket=daemon_socket,
                payload={
                    "configuration": configuration.document(cleanup_only=True),
                    "lease_id": value["lease_id"],
                    "manifest_sha256": reuse_manifest,
                },
            )
            if (
                readiness.get("format") != "lowerduckpond-m3-11-storage-admission-v1"
                or readiness.get("lease_id") != value["lease_id"]
                or readiness.get("manifest_sha256") != reuse_manifest
                or readiness.get("policy_sha256") != configuration.approved_policy_sha256
                or readiness.get("storage_target_sha256") != configuration.targets.storage_digest
                or readiness.get("helper_revision") != source
            ):
                raise LifecycleError("reused lease lacks current whole-bucket storage readiness")
            if readiness.get("whole_bucket_empty") is not True:
                raise StorageReadinessError(readiness.get("failure"))
            if readiness.get("failure") is not None:
                raise LifecycleError("storage readiness contradicts its provider diagnostic")
            # Execution-time observation does not renew the approval's own expiry.
            approval.validate(approved, mode=mode, now=datetime.now(UTC))
        run_id = str(uuid.uuid7())
        request = {
            "format": "lowerduckpond-m3-11-unattended-request-v2",
            "lease_id": value["lease_id"] or run_id,
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
            "daemon": prepared["daemon"],
        }
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
    extra: list[str] = []
    if action in {"cancel", "quiesce"}:
        mounts = value.get("Mounts")
        sources = (
            [
                row.get("Source")
                for row in mounts
                if isinstance(row, dict)
                and row.get("Destination") == SOCKET
                and row.get("Type") == "bind"
            ]
            if isinstance(mounts, list)
            else []
        )
        if (
            len(sources) != 1
            or not isinstance(sources[0], str)
            or not sources[0].startswith("/")
            or "," in sources[0]
        ):
            raise LifecycleError("original controller socket binding is unavailable")
        extra = [
            "--env",
            "DOCKER_HOST=unix://" + SOCKET,
            "--mount",
            f"type=bind,source={sources[0]},target={SOCKET}",
        ]
        if action == "cancel":
            extra.extend(
                ["--mount", f"type=volume,source={CLEANUP_VOLUME},target=/cleanup,readonly"]
            )
    return docker.command(
        "run",
        "--rm",
        "--network",
        "host" if action == "cancel" else "none",
        *extra,
        "--label",
        OWNER + "=true",
        "--mount",
        f"type=volume,source={helper_volume(source)},target=/opt/lifecycle,readonly",
        "--mount",
        f"type=volume,source={source_volume(source)},target=/work/source,readonly",
        "--mount",
        f"type=volume,source={EVIDENCE_VOLUME},target=/evidence"
        + ("" if action in {"cancel", "stop-attempt", "quiesce"} else ",readonly"),
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
        *(["--config", "/cleanup/cleanup.json"] if action == "cancel" else []),
    )


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("setup-template")
    initialize = subparsers.add_parser("setup")
    initialize.add_argument("--manifest", type=Path, required=True)
    initialize.add_argument("--output", type=Path, required=True)
    attest = subparsers.add_parser("attest-digitalocean")
    attest.add_argument("--token-reference", required=True)
    attest.add_argument("--generation", type=Path, required=True)
    attest.add_argument("--reader-config", type=Path, required=True)
    attest.add_argument("--observed-principal", required=True)
    attest.add_argument("--attested-by", required=True)
    attest.add_argument("--principal-context", required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--attest-provider-console", action="store_true", required=True)
    build = subparsers.add_parser("prepare")
    build.add_argument("revision")
    build.add_argument("--output", type=Path, required=True)
    run = subparsers.add_parser("start")
    run.add_argument("revision")
    run.add_argument("--approval", type=Path, required=True)
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--mode", choices=("rehearsal", "qualification"), required=True)
    run.add_argument("--daemon-socket", required=True)
    for name in ("status", "cancel", "stop-attempt", "quiesce", "evidence"):
        selected = subparsers.add_parser(name)
        selected.add_argument("run_id")
    return parser


def main() -> int:
    parser = argument_parser()
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == "setup-template":
            print(json.dumps(setup.template(), indent=2))
        elif args.action == "setup":
            setup.configure(args.manifest, args.output)
            print("Dedicated bootstrap configuration validated; no provider credential created.")
        elif args.action == "attest-digitalocean":
            setup.attest_digitalocean(
                reference=args.token_reference,
                generation=AuthorityGeneration.parse(read_private(args.generation)),
                reader_config=read_private(args.reader_config),
                observed_principal=args.observed_principal,
                attested_by=args.attested_by,
                principal_context=args.principal_context,
                output=args.output,
            )
            print("Bound metadata written privately; import it into the dedicated metadata item.")
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
    except StorageReadinessError as error:
        print(json.dumps(error.diagnostic, sort_keys=True), file=sys.stderr)
        parser.exit(1, "Reused lease storage is not ready; no attempt allocated.\n")
    except RuntimeError, OSError, ValueError, TypeError, KeyError:
        parser.exit(
            1,
            "Operation incomplete; preserve private volumes and reconcile credentials.\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
