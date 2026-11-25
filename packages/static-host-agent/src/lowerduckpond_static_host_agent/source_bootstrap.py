"""Pin reviewed source inputs before the existing installer can consume them."""

from __future__ import annotations

import grp
import json
import os
import sys
from urllib.parse import urlsplit

from lowerduckpond_static_contracts import decode_json_object

from lowerduckpond_static_host_agent.backup_identity import canonical_locator
from lowerduckpond_static_host_agent.disposable_routes import DisposableRoutes
from lowerduckpond_static_host_agent.droplet_enrollment import (
    ENROLLMENT,
    EXCLUSIONS,
    TARGET,
    validate_enrollment,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, StateAlreadyExistsError
from lowerduckpond_static_host_agent.host_restore_journal import full_id
from lowerduckpond_static_host_agent.host_restore_paths import private_directory
from lowerduckpond_static_host_agent.host_restore_runtime import install_runtime_input
from lowerduckpond_static_host_agent.installed_routing import (
    AUTHORITY,
    CADDY_ROOT,
    PROJECTION,
    ROLE,
    SOURCE_BOOTSTRAP,
    installed_projection,
    require_role,
)
from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    digest,
    encode,
    require,
)
from scripts.m3_12_droplet import require_metadata
from scripts.m3_12_droplet_observe import (
    _command,
    _restore_firewall,
    boot_sha256,
    metadata_identity,
    publication_state,
)
from scripts.m3_12_installed_root import predecessor_digest

FORMAT = "lowerduckpond-m3-12-source-bootstrap-v1"
INPUTS = {"artifactSha256", "repository", "backupRegion", "archiveBucket", "archiveRegion"}


def _document(raw: bytes) -> tuple[Document, DisposableRoutes]:
    document: Document = decode_json_object(raw)
    require(
        set(document)
        == {"format", "bootSha256", "predecessorSha256", "routing", "enrollment", *INPUTS}
        and document["format"] == FORMAT
        and encode(document) == raw
        and all(isinstance(document[key], str) for key in INPUTS)
        and isinstance(document["enrollment"], dict)
        and set(document["enrollment"]) == {TARGET, ENROLLMENT, EXCLUSIONS},
        "droplet-source-bootstrap-invalid",
    )
    full_id(document["artifactSha256"])
    full_id(document["bootSha256"])
    full_id(document["predecessorSha256"])
    repository = document["repository"]
    require(
        repository == canonical_locator(repository)
        and repository.startswith("s3:https://")
        and urlsplit(repository.removeprefix("s3:")).hostname
        == f"{document['backupRegion']}.digitaloceanspaces.com",
        "droplet-source-repository-changed",
    )
    return document, DisposableRoutes.from_bytes(encode(document["routing"]))


def _closed(owner: int) -> None:
    require(publication_state(owner) == "dark", "droplet-source-publication-open")
    firewall = _command("/usr/sbin/nft", "--json", "list", "table", "inet", "lowerduckpond_restore")
    require(_restore_firewall(json.loads(firewall)), "droplet-source-ingress-open")


def _retain(directory: DurableDirectory, name: str, raw: bytes, owner: int) -> None:
    try:
        directory.create_immutable((name,), raw)
    except StateAlreadyExistsError:
        require(_read(directory, name, owner) == raw, "droplet-source-bootstrap-conflict")


def _read(directory: DurableDirectory, name: str, owner: int) -> bytes:
    return directory.read_regular(
        (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
    )


def receive(raw: bytes, artifact: str, *, owner: int = 0) -> str:
    """Deliver the pinned scope to a fenced source with a stopped prior Caddy."""
    document, routing = _document(raw)
    require(
        document["artifactSha256"] == artifact
        and document["bootSha256"] == boot_sha256(owner)
        and document["predecessorSha256"] == predecessor_digest(),
        "droplet-source-bootstrap-target-changed",
    )
    records = {name: encode(row) for name, row in document["enrollment"].items()}
    identity = validate_enrollment(AUTHORITY, records.__getitem__, owner=owner)
    require(
        digest(identity.target) == routing.source_target
        and identity.registration["runId"] == routing.run_id,
        "droplet-source-bootstrap-target-changed",
    )
    require_metadata(identity, metadata_identity())
    _closed(owner)
    require(
        set(
            _command(
                "/usr/bin/systemctl",
                "show",
                "--property=ActiveState",
                "--property=UnitFileState",
                "caddy.service",
            ).splitlines()
        )
        == {"ActiveState=inactive", "UnitFileState=masked-runtime"},
        "droplet-source-caddy-not-fenced",
    )
    group = grp.getgrnam("caddy").gr_gid
    if not os.path.lexists(AUTHORITY.parent):
        private_directory(AUTHORITY.parent, owner=owner)
    private_directory(AUTHORITY, owner=owner)
    with (
        DurableDirectory.open(
            AUTHORITY, expected_owner=owner, expected_directory_mode=0o700
        ) as view,
        DurableDirectory.open(
            CADDY_ROOT, expected_owner=owner, expected_directory_mode=0o750
        ) as caddy,
    ):
        # Pin the requirement first. An interrupted delivery must never allow the
        # canonical Caddy bootstrap to run before the projection is complete.
        _retain(view, SOURCE_BOOTSTRAP, raw, owner)
        for name, payload in records.items():
            _retain(view, name, payload, owner)
        _retain(view, ROLE, encode(routing.role_document("source")), owner)
        install_runtime_input(
            caddy, PROJECTION, encode(routing.document()), owner=owner, group=group, mode=0o440
        )
    verify({key: document[key] for key in INPUTS}, artifact, owner=owner)
    return digest(document)


def require_source_projection(routing: DisposableRoutes, *, owner: int = 0) -> None:
    """Keep Caddy fenced until the retained handoff agrees with the installed projection."""
    with DurableDirectory.open(
        AUTHORITY, expected_owner=owner, expected_directory_mode=0o700
    ) as view:
        _, reviewed = _document(_read(view, SOURCE_BOOTSTRAP, owner))
    require(routing == reviewed, "droplet-source-projection-changed")


def verify(request: Document, artifact: str, *, owner: int = 0) -> None:
    """Validate effective installer inputs without reading any credentials."""
    with DurableDirectory.open(
        AUTHORITY, expected_owner=owner, expected_directory_mode=0o700
    ) as view:
        document, routing = _document(_read(view, SOURCE_BOOTSTRAP, owner))
    require(
        request == {key: document[key] for key in INPUTS}
        and artifact == document["artifactSha256"]
        and document["bootSha256"] == boot_sha256(owner)
        and document["predecessorSha256"] == predecessor_digest(),
        "droplet-source-site-inputs-changed",
    )
    require(installed_projection(owner=owner) == routing, "droplet-source-projection-changed")
    require_role(routing, "source", owner=owner)
    _closed(owner)


def main(artifact: str, operation: str) -> int:
    try:
        require(os.geteuid() == 0, "droplet-source-root-required")
        raw = sys.stdin.buffer.read(MAX_RECORD_BYTES + 1)
        if operation == "receive":
            print(receive(raw, artifact))
        else:
            require(operation == "verify", "droplet-source-operation-invalid")
            verify(decode_json_object(raw), artifact)
            print("verified")
        return 0
    except ValueError, RuntimeError, OSError, TypeError, KeyError:
        print("m3_12_source_bootstrap_refused", file=sys.stderr)
        return 2
