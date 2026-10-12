"""Synthetic subprocess/HTTP boundaries; application serializers and validators run unchanged.

Nothing here is a vendor capture or a claim about real JWT signatures/cache behavior.
Unexpected subprocesses fail closed instead of reaching a live service.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import pytest

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import operator_assemble as assembly

from .test_m3_11_lease_configuration import mapping
from .test_m3_11_operator_assemble import receipt_fixture

SOURCE = "e" * 40
ARTIFACT = b"SYNTHETIC-PREPARED-ARTIFACT"
DAEMON = dict.fromkeys(("ID", "Name", "DockerRootDir", "ServerVersion"), "synthetic-daemon")


class Services:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.local_run = subprocess.run
        self.local_popen = subprocess.Popen
        self.manifest, self.operator = receipt_fixture()
        self.calls: list[tuple[str, ...]] = []
        self.edits: list[dict[str, object]] = []
        self.exchanges: list[dict[str, object]] = []
        self.items: dict[tuple[str, str], dict[str, object]] = {}
        self.dirty = False
        self.unknown_source = False
        self.hide_metadata = False
        self.lost_edit = False
        self.change_before_edit = False
        self.op_version = "2.33.0"
        self.get_count = 0
        self.hidden: set[tuple[str, str]] = set()
        self.lose_post: str | None = None
        self.docker_handler: Callable[[list[str], bytes | None], bytes] | None = None
        self.transport_handler: (
            Callable[[str, list[str], bytes | None, dict[str, object]], bytes] | None
        ) = None
        self.http_handler: Callable[[dict[str, object]], dict[str, object]] | None = None
        for role, raw in mapping(self.manifest["providers"]).items():
            refs = mapping(mapping(raw)["references"])
            _, _, vault, item, field = str(refs["digitalocean"]).split("/")
            self.items[vault, item] = {
                "id": item,
                "vault": {"id": vault, "name": "Synthetic " + role},
                "category": "PASSWORD",
                "title": "Synthetic " + role,
                "version": 1,
                "fields": [
                    {
                        "id": field,
                        "label": field,
                        "type": "CONCEALED",
                        "purpose": "PASSWORD",
                        "value": self.operator.secrets[str(refs["digitalocean"])],
                    },
                    {
                        "id": "notesPlain",
                        "label": "notesPlain",
                        "type": "STRING",
                        "purpose": "NOTES",
                        "value": "Synthetic original notes",
                    },
                    {
                        "id": "unchanged",
                        "label": "retained",
                        "type": "STRING",
                        "section": {"id": "section-a"},
                        "value": "Synthetic original section",
                    },
                ],
                "sections": [{"id": "section-a", "label": "Original section"}],
                "urls": [{"href": "https://example.test", "primary": True}],
                "tags": ["synthetic-only", "preserve-me"],
                "favorite": True,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        original_which = shutil.which
        monkeypatch.setattr(
            shutil,
            "which",
            lambda name, **kwargs: (
                "/synthetic/" + name
                if name in {"op", "docker", "ssh", "gh"}
                else original_which(name, **kwargs)
            ),
        )
        monkeypatch.setattr(subprocess, "run", self.process)

    def git(self, arguments: list[str]) -> bytes:  # noqa: PLR0911 - explicit external protocol branches
        if arguments == ["rev-parse", "HEAD"]:
            return SOURCE.encode()
        if arguments == ["rev-parse", "--is-shallow-repository"]:
            return b"false"
        if arguments[:2] == ["status", "--porcelain"]:
            return b" M synthetic.py" if self.dirty else b""
        if arguments == ["merge-base", "--is-ancestor", SOURCE, SOURCE]:
            return b""
        if arguments[0] == "show":
            path = arguments[1].split(":", 1)[1]
            return (assembly.ROOT / path).read_bytes()
        if arguments[:2] == ["cat-file", "-e"]:
            if self.unknown_source:
                raise ValueError("synthetic unknown object")
            assert arguments[2] == SOURCE + "^{commit}"
            return b""
        if arguments[0] == "ls-tree":
            return ("100644 blob " + "a" * 40 + "\tsynthetic-input.txt\0").encode()
        if arguments[:2] == ["cat-file", "blob"]:
            return b"Synthetic committed input, not a deployed source capture."
        if arguments[:2] == ["bundle", "create"]:
            Path(arguments[2]).write_bytes(b"synthetic-git-bundle")
            return b""
        pytest.fail("unexpected Git operation: " + repr(arguments))

    def native(self, arguments: list[str], stdin: bytes | None) -> bytes:
        if arguments == ["--version"]:
            return self.op_version.encode()
        if arguments[:2] not in (["item", "get"], ["item", "edit"]):
            assert stdin is None
            return self.operator.command(*arguments)
        assert arguments[-8:] == [
            "--vault",
            arguments[4],
            "--account",
            "A" * 26,
            "--format",
            "json",
            "--reveal",
            "--cache=false",
        ]
        key = arguments[4], arguments[2]
        if arguments[1] == "get":
            self.get_count += 1
            if self.change_before_edit and self.get_count == 2:  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
                self.items[key]["title"] = "Synthetic concurrent edit"
            return canonical_bytes(self.items[key])
        assert stdin is not None
        submitted = json.loads(stdin)
        self.edits.append(deepcopy(submitted))
        self.items[key] = {**submitted, "version": cast(int, submitted["version"]) + 1}
        if self.lost_edit:
            raise subprocess.TimeoutExpired("synthetic-op", 90)
        return canonical_bytes(self.items[key])

    def connect(self, value: dict[str, object]) -> dict[str, object]:  # noqa: PLR0911 - explicit external protocol branches
        self.exchanges.append(deepcopy(value))
        encoded = str(value["token"]).split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        assert str(value["token"]) in self.operator.secrets.values()
        grants = {row["u"].lower(): row["a"] for row in claims["1password.com/vts"]}
        path, method = urlsplit(str(value["url"])).path, value["method"]
        if path == "/v1/vaults":
            return {
                "status": 200,
                "body": [{"id": key, "name": "Synthetic vault"} for key in grants],
            }
        parts = path.split("/")
        vault = parts[3]
        if vault not in grants:
            return {"status": 403, "body": None}
        if len(parts) == 4:  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
            return {"status": 200, "body": {"id": vault}}
        if len(parts) == 5 and method == "POST":  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
            assert grants[vault] == 496  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
            item_id = (
                hashlib.sha256(str(len(self.items)).encode())
                .hexdigest()[:26]
                .translate(str.maketrans("0123456789", "ghijklmnop"))
            )
            row = {**mapping(value["body"]), "id": item_id, "version": 1}
            self.items[vault, item_id] = row
            if self.lose_post and self.lose_post in str(row["title"]):
                self.hidden.add((vault, item_id))
                self.lose_post = None
                raise subprocess.TimeoutExpired("synthetic-lost-POST-response", 30)
            return {"status": 200, "body": deepcopy(row)}
        assert method == "GET"
        if len(parts) == 5:  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
            return {
                "status": 200,
                "body": [
                    deepcopy(row)
                    for (owned, _item), row in self.items.items()
                    if owned == vault and (owned, _item) not in self.hidden
                ],
            }
        if (vault, parts[5]) not in self.items or (vault, parts[5]) in self.hidden:
            return {"status": 404, "body": None}
        item = deepcopy(self.items[vault, parts[5]])
        if self.hide_metadata:
            item["fields"] = [
                row
                for row in cast(list[dict[str, object]], item["fields"])
                if row.get("label") != "digitalocean_metadata"
            ]
        return {"status": 200, "body": item}

    def process(self, arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(tuple(arguments))
        program = Path(arguments[0]).name
        stdin = cast(bytes | None, kwargs.get("input"))
        if program == "op":
            environment = cast(dict[str, str], kwargs["env"])
            assert (
                not {"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_DEBUG"}
                & environment.keys()
            )
            output = self.native(arguments[1:], stdin)
        elif program == "git":
            output = self.git(arguments[4:])
        elif arguments[1:] == ["-m", "scripts.m3_11_unattended.connect_api", "--exchange"]:
            assert stdin is not None
            output = json.dumps(self.connect(json.loads(stdin))).encode()
        elif program == "docker" and self.docker_handler is not None:
            output = self.docker_handler(arguments[1:], stdin)
        elif (
            arguments[1:] == ["-m", "scripts.m3_11_unattended.http", "--exchange"]
            and self.http_handler is not None
        ):
            assert stdin is not None
            output = json.dumps(self.http_handler(json.loads(stdin))).encode()
        elif self.transport_handler is not None:
            output = self.transport_handler(program, arguments[1:], stdin, kwargs)
        else:
            pytest.fail("unexpected external process: " + repr(arguments))
        return subprocess.CompletedProcess(arguments, 0, output, b"")

    def stage(self, directory: Path) -> tuple[Path, Path, str]:
        from scripts.m3_11_private_inputs import read_private, write_private  # noqa: PLC0415

        directory.chmod(0o700)
        manifest = directory / "bound-inputs.json"
        if manifest.exists():
            assert read_private(manifest) == self.manifest
        else:
            write_private(manifest, self.manifest)
        master = directory / "synthetic-master.json"
        write_private(master, {"synthetic": "DUMMY-INDEPENDENT-MASTER"})
        staged = directory / "staged"
        assembly.run(self.manifest, output=staged, credentials=master)
        return (
            manifest,
            staged,
            hashlib.sha256((staged / "controller-connect.json").read_bytes()).hexdigest(),
        )
