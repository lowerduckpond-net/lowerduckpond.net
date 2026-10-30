"""Strict public binding of genuine native local reconstruction prerequisites."""

from __future__ import annotations

from typing import cast

from scripts.m3_11_isolation_contract import CONTEXT_FORMAT, ROLES, Plan, provider_id
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import digest, fingerprint, identity, instant, strings

FORMAT = "lowerduckpond-isolated-public-ca-prepared-v1"
ACTORS = frozenset({"source", "destination", "acme", "archive", "controller"})


def parse(raw: object) -> dict[str, object]:
    value = fields(
        raw,
        {
            "format",
            "run_id",
            "source_revision",
            "artifact_sha256",
            "caddy_binary_sha256",
            "daemon_sha256",
            "original_inputs_sha256",
            "source_fence_sha256",
            "guest_program_sha256",
            "restore",
            "actors",
            "captured_at",
            "topology",
        },
    )
    if value["format"] != FORMAT:
        raise ValueError("isolated preparation format differs")
    identity(value["run_id"])
    from scripts.production_qualification_inputs import revision  # noqa: PLC0415

    revision(value["source_revision"])
    for key in (
        "artifact_sha256",
        "caddy_binary_sha256",
        "daemon_sha256",
        "original_inputs_sha256",
        "source_fence_sha256",
        "guest_program_sha256",
    ):
        fingerprint(value[key])
    instant(value["captured_at"])
    restore = fields(
        value["restore"], {"restore_id", "journal_sha256", "binary_sha256", "public_store_absent"}
    )
    identity(restore["restore_id"])
    fingerprint(restore["journal_sha256"])
    if (
        restore["binary_sha256"] != value["caddy_binary_sha256"]
        or restore["public_store_absent"] is not True
    ):
        raise ValueError("isolated preparation has no genuine cold reconstruction")
    actors = fields(value["actors"], set(ACTORS))
    ids: set[str] = set()
    for name, raw_actor in actors.items():
        actor = fields(raw_actor, {"id", "name", "image", "owner"})
        ids.add(fingerprint(actor["id"]))
        run_id = str(value["run_id"]).replace("-", "")
        expected = (
            "/ldp-m311-public-ca-" + run_id
            if name == "controller"
            else f"/ldp-m3-{run_id}-{'host' if name == 'source' else name}"
        )
        if (
            actor["name"] != expected
            or actor["owner"] != run_id
            or not isinstance(actor["image"], str)
            or not actor["image"].startswith("sha256:")
        ):
            raise ValueError("isolated prepared actor belongs to another resource graph")
        fingerprint(actor["image"].removeprefix("sha256:"))
    if len(ids) != len(ACTORS):
        raise ValueError("isolated prepared actors repeat an identity")
    topology = fields(value["topology"], {"docker_endpoint", "daemon", "network_modes"})
    daemon = strings(fields(topology["daemon"], {"ID", "Name", "DockerRootDir", "ServerVersion"}))
    if any(not item or any(ord(char) < 32 for char in item) for item in daemon.values()):  # noqa: PLR2004
        raise ValueError("isolated prepared daemon metadata is invalid")
    if digest(topology["daemon"]) != value["daemon_sha256"] or topology["network_modes"] != {
        name: "host" if name == "controller" else "bridge" for name in ACTORS
    }:
        raise ValueError("isolated prepared daemon or native network path differs")
    return value


def require(raw: object, plan: Plan) -> dict[str, object]:
    value = parse(raw)
    if digest(value) != plan.preparation_sha256 or any(
        value[key] != getattr(plan, key)
        for key in (
            "run_id",
            "source_revision",
            "artifact_sha256",
            "caddy_binary_sha256",
            "daemon_sha256",
        )
    ):
        raise ValueError("isolated prepared evidence differs from the exact plan")
    topology = cast(dict[str, object], value["topology"])
    if topology["docker_endpoint"] != plan.docker_endpoint:
        raise ValueError("isolated prepared Docker endpoint differs")
    for name, actor in cast(dict[str, dict[str, object]], value["actors"]).items():
        expected = (
            plan.controller_sha256
            if name == "controller"
            else plan.archive_image_sha256
            if name == "archive"
            else plan.fixture_image_sha256
        )
        if actor["image"] != "sha256:" + expected:
            raise ValueError("isolated prepared image differs from the plan")
    return value


def context(  # noqa: PLR0913 - exact credential/context bindings
    raw: object,
    prepared: object,
    plan: Plan,
    *,
    intents: dict[str, str],
    ids: dict[str, str],
    expires_at: str,
) -> dict[str, object]:
    original = require(prepared, plan)
    value = fields(
        raw,
        {
            "format",
            "plan_sha256",
            "run_id",
            "captured_at",
            "source_fixture_sha256",
            "actors",
            "topology",
            "guest_program_sha256",
            "preparation_sha256",
            "credentials",
        },
    )
    for selected in ids.values():
        provider_id(selected)
    if set(ids) != ROLES or len(set(ids.values())) != len(ROLES):
        raise ValueError("isolated context credential identities differ")
    if (
        value["format"] != CONTEXT_FORMAT
        or value["plan_sha256"] != plan.sha256
        or value["run_id"] != plan.run_id
        or value["preparation_sha256"] != plan.preparation_sha256
        or value["source_fixture_sha256"]
        != digest(cast(dict[str, object], original["actors"])["source"])
        or value["actors"] != original["actors"]
        or value["topology"] != original["topology"]
        or value["guest_program_sha256"] != original["guest_program_sha256"]
        or value["credentials"] != {"ids": ids, "intents": intents, "expires_at": expires_at}
        or not instant(original["captured_at"])
        <= instant(value["captured_at"])
        < instant(expires_at)
    ):
        raise ValueError("isolated public context differs from its genuine prepared graph")
    return value
