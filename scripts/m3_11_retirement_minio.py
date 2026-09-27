"""Observe the unused local service without adopting its missing historical ID."""

from __future__ import annotations

import hashlib

import docker  # type: ignore[import-untyped]

from scripts import qualification_restore as owned
from scripts.m3_11_retirement_context import Context
from scripts.m3_11_retirement_files import RetirementError, digest
from scripts.qualification_context import ARCHIVE_ENV, RUN_ENV


def variables(value: object) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > 64:  # noqa: PLR2004
        raise RetirementError("unused MinIO environment is unbounded")
    result = {}
    for item in value:
        if not isinstance(item, str) or "=" not in item or len(item) > 4096:  # noqa: PLR2004
            raise RetirementError("unused MinIO environment is invalid")
        key, item_value = item.split("=", 1)
        if not key or key in result:
            raise RetirementError("unused MinIO environment is ambiguous")
        result[key] = item_value
    return result


def observe(context: Context, api: docker.APIClient) -> dict[str, object]:
    environment = context.environment
    identity = owned.inspect(environment, environment[ARCHIVE_ENV])
    if (
        identity["name"] != "/" + environment[ARCHIVE_ENV]
        or identity["owner"] != environment[RUN_ENV]
    ):
        raise RetirementError("unused MinIO is not the saved local name")
    raw = api.inspect_container(identity["id"])
    image = api.inspect_image(identity["image"])
    recipe = owned.command(
        environment,
        "git",
        "show",
        str(context.context["source_revision"])
        + ":config/ansible/molecule/m3_8/Dockerfile.minio.j2",
    )
    recipe_digest = hashlib.sha256(recipe).hexdigest()
    image_config, config, host = image["Config"], raw["Config"], raw["HostConfig"]
    expected = {
        **variables(image_config["Env"]),
        "MINIO_ROOT_USER": "molecule-m3-10-root",
        "MINIO_ROOT_PASSWORD": "molecule-m3-10-disposable-root-secret",  # gitleaks:allow
        "MINIO_REGION_NAME": "ams3",
    }
    if (
        image_config["Labels"].get("net.lowerduckpond.fixture.minio-recipe") != recipe_digest
        or config["Image"] != "ldp-minio-fixture:" + recipe_digest
        or config["Entrypoint"] != ["/usr/bin/minio"]
        or raw["Path"] != "/usr/bin/minio"
        or config["Cmd"] != ["server", "/data", "--address", ":443", "--certs-dir", "/certs"]
        or raw["Args"] != config["Cmd"]
        or variables(config["Env"]) != expected
        or host["Privileged"] is not False
        or raw["Mounts"]
        or any(
            host.get(key)
            for key in (
                "Binds",
                "VolumesFrom",
                "CapAdd",
                "Devices",
                "DeviceRequests",
                "SecurityOpt",
            )
        )
        or any(host.get(key) for key in ("PidMode", "UTSMode", "UsernsMode"))
        or host.get("IpcMode") not in {None, "", "private"}
        or host["NetworkMode"] not in {"default", "bridge"}
        or environment["M3_10_ARCHIVE_BACKEND"] != "spaces"
        or environment["M3_11_COMBINED_BACKEND"] != "spaces"
    ):
        raise RetirementError("unused MinIO cannot be excluded from Spaces writers")
    # Current metadata supports exclusion only. It never authorizes a stop or
    # claims this container is the historical instance that created the run.
    return {
        "current_id": identity["id"],
        "image": identity["image"],
        "configuration_sha256": digest({"config": config, "host": host, "mounts": raw["Mounts"]}),
        "authority": "observation-only; leave-untouched",
    }
