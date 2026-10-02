"""Finish debugging an abandoned M3.11 run by disposing of its owned resources.

Preview by default. --discard declares debugging finished and removes the
run's Spaces backup prefix, Docker fixtures/image, and private run directory.
Resolve any remaining shared archive objects or DNS challenges first.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import S3Client, assert_storage_empty, create_client
from lowerduckpond_static_host_agent.durable import DurableDirectory

from scripts import m3_11_backup_discard as backups
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.check_m3_7_production_edge import CloudflareClient, _require_zone_identity
from scripts.m3_11_backup_fixture import Target, _version
from scripts.m3_11_backup_removal import Removal, _once
from scripts.m3_11_combined_inputs import FORMAT, _directory, _environment, environment_for
from scripts.m3_11_dns_witness import ZONES, DnsWitness
from scripts.m3_11_live_storage import FORMAT as STORAGE_FORMAT
from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.qualification_case import remove_owned_image
from scripts.qualification_context import IMAGE_ENV, RUN_ENV, run_lease
from scripts.qualification_storage_lease import storage_lease

LABEL = "lowerduckpond.qualification.run"
ROLES = ("destination", "host", "acme", "archive")
IDENTITY = ("id", "name", "owner", "image")
DISPOSAL_FORMAT = "lowerduckpond-m3-11-debug-directory-disposal-v1"


class CloseoutError(ValueError):
    """A fixed operator explanation without private provider or fixture data."""


def disposal_receipt(run: Path) -> Path:
    return run.with_name(run.name + ".debug-closeout.json")


def finish_directory(run: Path, *, apply: bool) -> None:
    """Resume local deletion after cloud and Docker absence were already proved."""
    _directory(run.parent)
    receipt = disposal_receipt(run)
    descriptor = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CloseoutError("directory disposal is already running") from error
        metadata = os.fstat(descriptor)
        saved = evidence.fields(
            read_private(receipt), {"format", "directory", "device", "inode", "fixture"}
        )
        fixture = evidence.fields(saved["fixture"], {"format", "run_id", "environment"})
        run_id = str(evidence.uuid7(fixture["run_id"]))
        environment = fixture["environment"]
        endpoint = environment.get("DOCKER_HOST") if isinstance(environment, dict) else None
        if (
            saved["format"] != DISPOSAL_FORMAT
            or saved["directory"] != str(run)
            or type(saved["device"]) is not int
            or type(saved["inode"]) is not int
            or saved["device"] < 0
            or saved["inode"] <= 0
            or fixture["format"] != FORMAT
            or not isinstance(endpoint, str)
            or not endpoint.startswith("unix:///")
            or environment != _environment(run, run_id, endpoint)
        ):
            raise CloseoutError("directory disposal lost its original identity")
        if run.exists() or run.is_symlink():
            _directory(run)
            if (run.stat().st_dev, run.stat().st_ino) != (saved["device"], saved["inode"]):
                raise CloseoutError("directory was replaced after disposal authorization")
            manifest = run / "fixture.json"
            if (manifest.exists() or manifest.is_symlink()) and read_private(manifest) != fixture:
                raise CloseoutError("run manifest changed after disposal authorization")
        if not apply:
            print("Local directory disposal remains. Add --discard to finish it.")
            return
        if run.exists():
            shutil.rmtree(run)
        with DurableDirectory.open(
            run.parent, expected_owner=os.geteuid(), expected_directory_mode=0o700
        ) as parent:
            parent_fd = parent.duplicate_descriptor()
            try:
                os.fsync(parent_fd)  # Persist root removal before deleting its retry receipt.
            finally:
                os.close(parent_fd)
            current = receipt.lstat()
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise CloseoutError("directory disposal receipt was replaced")
            parent.remove((receipt.name,))
        print(
            "Debugging closed: remote backups and local resources removed; attempt remains failed."
        )
    finally:
        os.close(descriptor)


def stage_directory(run: Path, fixture: dict[str, object], identity: tuple[int, int]) -> None:
    _directory(run.parent)
    raw = evidence.canonical_bytes(
        {
            "format": DISPOSAL_FORMAT,
            "directory": str(run),
            "device": identity[0],
            "inode": identity[1],
            "fixture": fixture,
        }
    )
    if len(raw) > evidence.MAX_BYTES:
        raise CloseoutError("directory disposal receipt exceeds its byte bound")
    with DurableDirectory.open(
        run.parent, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as parent:
        parent.create_immutable((disposal_receipt(run).name,), raw)
    finish_directory(run, apply=True)


def target_for(run: Path, environment: Mapping[str, str]) -> Target:
    manifest = read_private(run / "fixture.json")
    target = Target(
        str(manifest["run_id"]),
        environment["SPACES_REGION"],
        environment["SPACES_BACKUP_BUCKET"],
        environment["SPACES_ARCHIVE_BUCKET"],
    )
    captured = run / "qualification-inputs.json"
    if (
        captured.exists()
        and read_private(captured).get("storage_target_sha256") != target.storage_target_sha256
    ):
        raise CloseoutError("current Spaces target differs from the failed run")
    captured = run / "live-storage.json"
    if captured.exists():
        value = read_private(captured)
        if any(
            value.get(key) != expected
            for key, expected in {
                "run_id": target.run_id,
                "region": target.region,
                "backup_bucket": target.backup_bucket,
                "archive_bucket": target.archive_bucket,
            }.items()
        ):
            raise CloseoutError("saved Spaces target differs from the failed run")
    return target


def containers(environment: dict[str, str]) -> dict[str, dict[str, object]]:
    ids: set[str] = set()
    # A replacement can retain the expected name without the original label.
    # Separate inventories find it as well as unexpected names with our label.
    for selector in (
        f"label={LABEL}={environment[RUN_ENV]}",
        f"name=^/ldp-m3-{environment[RUN_ENV]}-({'|'.join(ROLES)})$",
    ):
        raw = owned.command(
            environment,
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            selector,
            "--format",
            "{{.ID}}",
        )
        listed = raw.decode("ascii").splitlines()
        if len(listed) != len(set(listed)):
            raise CloseoutError("Docker returned an ambiguous run inventory")
        ids.update(listed)
    names = {f"/ldp-m3-{environment[RUN_ENV]}-{role}" for role in ROLES}
    if len(ids) > len(ROLES):
        raise CloseoutError("Docker returned an ambiguous run inventory")
    result = {}
    for identity in ids:
        if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise CloseoutError("Docker returned an invalid container identity")
        row = owned.inspect(environment, identity)
        if row["id"] != identity or row["name"] not in names:
            raise CloseoutError("an unexpected container carries this run's ownership label")
        result[identity] = row
    if len({row["name"] for row in result.values()}) != len(result):
        raise CloseoutError("Docker returned duplicate fixture names")
    return result


def image(environment: dict[str, str]) -> str:
    identity = (
        owned.command(
            environment,
            "docker",
            "image",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            f"reference=molecule_local/{environment[IMAGE_ENV]}",
            "--format",
            "{{.ID}}",
        )
        .decode("ascii")
        .strip()
    )
    if identity and re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is None:
        raise CloseoutError("Docker returned an ambiguous image identity")
    return identity


def local_intent(
    run: Path, environment: dict[str, str], rows: dict[str, dict[str, object]]
) -> dict[str, object]:
    """Keep original local identities through partial container/image removal."""
    path = run / "debug-closeout-local.json"
    fixture = read_private(run / "fixture.json")
    if path.exists() or path.is_symlink():
        value = evidence.fields(read_private(path), {"fixture", "containers", "image"})
        saved = value["containers"]
        if (
            value["fixture"] != fixture
            or not isinstance(saved, dict)
            or any(
                {key: row[key] for key in IDENTITY} != saved.get(identity)
                for identity, row in rows.items()
            )
        ):
            raise CloseoutError("local resources differ from closeout authorization")
    else:
        images = {
            row["image"]
            for row in rows.values()
            if row["name"] == f"/ldp-m3-{environment[RUN_ENV]}-host"
        }
        source = run / "restore/source.json"
        if source.exists():
            images.add(read_private(source).get("image"))
        if len(images) > 1 or (not images and image(environment)):
            raise CloseoutError("run image lacks its original fixture identity")
        value = {
            "fixture": fixture,
            "containers": {
                identity: {key: row[key] for key in IDENTITY} for identity, row in rows.items()
            },
            "image": images.pop() if images else "",
        }
    expected = value["image"]
    if not isinstance(expected, str) or (
        expected and re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is None
    ):
        raise CloseoutError("invalid original fixture image")
    if image(environment) not in {"", expected}:
        raise CloseoutError("owned image tag was replaced")
    return value


def require_bound_containers(run: Path, rows: dict[str, dict[str, object]]) -> None:
    owner = evidence.uuid7(read_private(run / "fixture.json")["run_id"]).hex
    for kind in ("source", "destination", "acme"):
        path = run / f"restore/{kind}.json"
        if path.exists():
            saved = json.loads(read_private_bytes(path))
            role = "host" if kind == "source" else kind
            if saved.get("name") != f"/ldp-m3-{owner}-{role}" or saved.get("owner") != owner:
                raise CloseoutError("a saved fixture receipt has foreign ownership")
            for row in rows.values():
                if row["name"] == saved.get("name") and any(
                    row[key] != saved.get(key) for key in IDENTITY
                ):
                    raise CloseoutError("a recorded fixture container was replaced")


def require_same(
    environment: dict[str, str], expected: dict[str, dict[str, object]], *, stopped: bool = False
) -> None:
    actual = containers(environment)
    if set(actual) != set(expected) or any(
        any(row[key] != expected[identity][key] for key in IDENTITY)
        or (stopped and row["running"] is not False)
        for identity, row in actual.items()
    ):
        raise CloseoutError("fixture ownership changed or a stopped writer restarted")


def dns_absent(run: Path, environment: Mapping[str, str], target: Target) -> None:
    names_path = run / "combined-names.json"
    if not names_path.exists():
        return
    names = read_private(names_path)
    context_path = run / "combined-context.json"
    # Names are written before the context; a crash between those writes is
    # still disposable after independently checking its exact DNS subjects.
    context: dict[str, object] = (
        read_private(context_path)
        if context_path.exists()
        else {
            "run_id": target.run_id,
            "subject_set_sha256": evidence.subject_digest(names.get("nonce")),
        }
    )
    evidence.validate_names(names_path, context)
    if context["run_id"] != target.run_id:
        raise CloseoutError("DNS names belong to another qualification")
    nonce = evidence.uuid7(names["nonce"]).hex
    client = CloudflareClient(environment["CLOUDFLARE_API_TOKEN"])
    coordinates = tuple(
        (domain, environment[variable], f"_acme-challenge.m3-11-{nonce}.{domain}")
        for domain, variable in ZONES
    )
    if (
        len({zone for _, zone, _ in coordinates}) != len(ZONES)
        or len({_require_zone_identity(client, zone, domain) for domain, zone, _ in coordinates})
        != 1
    ):
        raise CloseoutError("DNS zone ownership differs from the qualification")
    witness = DnsWitness(run, client, "", "", coordinates)
    if any(witness._records(zone, name) for _, zone, name in coordinates):
        raise CloseoutError("retire this run's stale DNS challenges before closeout")


def cloud_absent(
    run: Path, environment: Mapping[str, str], target: Target, client: S3Client
) -> None:
    # This Space is shared with production: observe it, never bulk-delete it.
    try:
        assert_storage_empty(client, bucket=target.archive_bucket)
    except RuntimeError as error:
        raise CloseoutError(
            "shared archive Space is nonempty or unavailable; "
            "resolve owned archives before closeout"
        ) from error
    dns_absent(run, environment, target)


def backup_removal(
    run: Path, environment: dict[str, str], quiescent: Callable[[], str]
) -> Removal | None:
    path = run / "live-storage.json"
    if not path.exists():
        return None
    target = target_for(run, environment)
    storage = read_private(path)
    if storage.get("format") != STORAGE_FORMAT:
        raise CloseoutError("invalid saved Spaces ownership")
    binding = evidence.fields(storage.get("binding"), evidence.BINDING_FIELDS)
    writer, observer = target.clients(environment)
    removal = Removal(
        target,
        binding,
        _version(storage.get("owner_version")),
        writer,
        observer,
        run / "debug-closeout-backup",
        quiescent,
    )
    removal.preflight()
    return removal


def stop_containers(environment: dict[str, str], before: dict[str, dict[str, object]]) -> None:
    for role in ROLES:
        for identity, row in before.items():
            if row["name"] == f"/ldp-m3-{environment[RUN_ENV]}-{role}" and row["running"]:
                require_same(environment, before)
                owned.command(environment, "docker", "stop", "--time", "60", identity, timeout=75)
    require_same(environment, before, stopped=True)


def remove_containers(environment: dict[str, str], before: dict[str, dict[str, object]]) -> None:
    for identity in before:
        require_same(environment, before, stopped=True)
        owned.command(environment, "docker", "container", "rm", "--volumes", identity)
        before = {key: row for key, row in before.items() if key != identity}
    require_same(environment, {}, stopped=True)


def resume_directory(run: Path, *, apply: bool) -> bool:
    receipt = disposal_receipt(run)
    if not (receipt.exists() or receipt.is_symlink()):
        return False
    with ExitStack() as locks:
        if (run / "run.lock").exists():
            locks.enter_context(run_lease(run))
        finish_directory(run, apply=apply)
    return True


def closeout(run: Path, ambient: Mapping[str, str], *, apply: bool) -> None:
    if resume_directory(run, apply=apply):
        return
    _directory(run)
    original_inode = run.stat().st_dev, run.stat().st_ino
    original = read_private(run / "fixture.json")
    if (run / "qualification.json").exists():
        raise CloseoutError("debug closeout accepts abandoned attempts, not passing qualifications")
    saved = cast("dict[str, str]", original["environment"])
    current = {**ambient, "DOCKER_HOST": saved["DOCKER_HOST"]}
    current.pop("DOCKER_CONTEXT", None)
    environment = environment_for(run, current)
    target = target_for(run, environment)
    with storage_lease(environment), ExitStack() as locks:
        lock = run / "run.lock"
        if lock.exists() or apply:
            locks.enter_context(run_lease(run, create=not lock.exists()))
        before = containers(environment)
        require_bound_containers(run, before)
        intent = local_intent(run, environment, before)
        client = create_client(
            access_key_id=environment["SPACES_ACCESS_KEY_ID"],
            secret_access_key=environment["SPACES_SECRET_ACCESS_KEY"],
            region=target.region,
            endpoint_url=f"https://{target.region}.digitaloceanspaces.com",
        )
        cloud_absent(run, environment, target, client)

        def quiescent() -> str:
            require_same(environment, before, stopped=True)
            local_intent(run, environment, before)
            cloud_absent(run, environment, target, client)
            return hashlib.sha256(evidence.canonical_bytes(intent)).hexdigest()

        removal = backup_removal(run, environment, quiescent)
        if removal is None:
            assert_storage_empty(client, bucket=target.backup_bucket, prefix=target.prefix)
        # Remote inventory errors must leave the original local fixture available.
        backup_inventory = backups.inventory(
            client, bucket=target.backup_bucket, prefix=target.prefix
        )
        print(
            f"Remote closeout: {len(backup_inventory.versions)} versions/delete markers, "
            f"{len(backup_inventory.uploads)} uploads under "
            f"{target.backup_bucket}/{target.prefix}.",
            flush=True,
        )
        print(
            f"Local closeout: {len(before)} containers, the run image tag, and {run}.", flush=True
        )
        if not apply:
            print("Add --discard when debugging is finished to remove these resources.")
            return
        _once(run / "debug-closeout-local.json", intent)
        stop_containers(environment, before)
        cloud_absent(run, environment, target, client)
        if removal is not None:
            removal.run()
        else:
            assert_storage_empty(client, bucket=target.backup_bucket, prefix=target.prefix)
        require_same(environment, before, stopped=True)
        cloud_absent(run, environment, target, client)
        remove_containers(environment, before)
        local_intent(run, environment, {})
        remove_owned_image(environment, expected_image=str(intent["image"]))
        assert_storage_empty(client, bucket=target.backup_bucket, prefix=target.prefix)
        cloud_absent(run, environment, target, client)
        _directory(run)
        if (run.stat().st_dev, run.stat().st_ino) != original_inode or read_private(
            run / "fixture.json"
        ) != original:
            raise CloseoutError("run manifest changed before directory removal")
        stage_directory(run, original, original_inode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--discard",
        action="store_true",
        help="finish debugging and permanently dispose of this run",
    )
    args = parser.parse_args()
    try:
        closeout(args.directory, os.environ, apply=args.discard)
    except Exception as error:
        message = str(error) if isinstance(error, CloseoutError) else type(error).__name__
        print(
            f"Debug closeout incomplete: {message}. Rerun the same directory after resolving it.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
