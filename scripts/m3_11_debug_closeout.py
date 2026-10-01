"""Finish debugging an abandoned M3.11 run by disposing of its owned resources.

Preview by default. --discard declares debugging finished and removes the
run's Spaces backup prefix, Docker fixtures/image, and private run directory.
Resolve any remaining shared archive objects or DNS challenges first.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import S3Client, assert_storage_empty, create_client

from scripts import m3_11_backup_discard as backups
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.check_m3_7_production_edge import CloudflareClient, _require_zone_identity
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_combined_inputs import _directory, environment_for
from scripts.m3_11_dns_witness import ZONES, DnsWitness
from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.qualification_case import remove_owned_image
from scripts.qualification_context import RUN_ENV, run_lease
from scripts.qualification_storage_lease import storage_lease

LABEL = "lowerduckpond.qualification.run"
ROLES = ("destination", "host", "acme", "archive")
IDENTITY = ("id", "name", "owner", "image")


class CloseoutError(ValueError):
    """A fixed operator explanation without private provider or fixture data."""


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
    raw = owned.command(
        environment,
        "docker",
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        f"label={LABEL}={environment[RUN_ENV]}",
        "--format",
        "{{.ID}}",
    )
    ids = raw.decode("ascii").splitlines()
    names = {f"/ldp-m3-{environment[RUN_ENV]}-{role}" for role in ROLES}
    if len(ids) > len(ROLES) or len(set(ids)) != len(ids):
        raise CloseoutError("Docker returned an ambiguous run inventory")
    result = {}
    for identity in ids:
        if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise CloseoutError("Docker returned an invalid container identity")
        row = owned.inspect(environment, identity)
        if row["name"] not in names:
            raise CloseoutError("an unexpected container carries this run's ownership label")
        result[identity] = row
    if len({row["name"] for row in result.values()}) != len(result):
        raise CloseoutError("Docker returned duplicate fixture names")
    return result


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


def closeout(run: Path, ambient: Mapping[str, str], *, apply: bool) -> None:
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
        client = create_client(
            access_key_id=environment["SPACES_ACCESS_KEY_ID"],
            secret_access_key=environment["SPACES_SECRET_ACCESS_KEY"],
            region=target.region,
            endpoint_url=f"https://{target.region}.digitaloceanspaces.com",
        )
        cloud_absent(run, environment, target, client)
        if not (run / "qualification-inputs.json").exists():
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
        for role in ROLES:
            for identity, row in before.items():
                if row["name"] == f"/ldp-m3-{environment[RUN_ENV]}-{role}" and row["running"]:
                    require_same(environment, before)
                    owned.command(
                        environment, "docker", "stop", "--time", "60", identity, timeout=75
                    )
        require_same(environment, before, stopped=True)
        cloud_absent(run, environment, target, client)
        backups.run(client, bucket=target.backup_bucket, targets=[target.run_id], apply=True)
        require_same(environment, before, stopped=True)
        cloud_absent(run, environment, target, client)
        for identity in before:
            require_same(environment, before, stopped=True)
            owned.command(environment, "docker", "container", "rm", "--volumes", identity)
            before = {key: row for key, row in before.items() if key != identity}
        require_same(environment, {}, stopped=True)
        remove_owned_image(environment)
        assert_storage_empty(client, bucket=target.backup_bucket, prefix=target.prefix)
        cloud_absent(run, environment, target, client)
        _directory(run)
        if (run.stat().st_dev, run.stat().st_ino) != original_inode or read_private(
            run / "fixture.json"
        ) != original:
            raise CloseoutError("run manifest changed before directory removal")
        shutil.rmtree(run)
        print(
            "Debugging closed: remote backups and local resources removed; attempt remains failed."
        )


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
