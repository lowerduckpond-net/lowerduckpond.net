from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from scripts import qualification_minio as fixture


def test_molecule_uses_the_same_recipe_bound_image_as_the_controller() -> None:
    configuration = yaml.safe_load((fixture.RECIPE.parent / "molecule.yml").read_text())
    assert configuration["platforms"][1]["image"] == fixture.image_reference()


@pytest.mark.parametrize("cached", [True, False])
def test_local_build_is_reused_and_never_transfers_a_workspace_context(
    monkeypatch: pytest.MonkeyPatch, cached: bool
) -> None:
    ready = cached
    built = []
    environment = {"DOCKER_HOST": "unix:///owned-fixture.sock"}
    reference = fixture.image_reference()

    def command(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal ready
        assert kwargs["env"] == environment
        if args[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(
                args, 0 if ready else 1, json.dumps(reference.split(":")[1]) if ready else ""
            )
        assert Path(args[0]).name == "docker" and args[1] == "build" and args[-1] == "-"
        assert kwargs["input"] == fixture.RECIPE.read_bytes()
        assert "--build-arg" not in args
        built.append(args)
        ready = True
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", command)
    assert fixture.ensure_image(environment) == reference
    assert len(built) == (0 if cached else 1)


def test_foreign_image_at_the_recipe_tag_is_rejected_without_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def command(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps("unrelated-build"))

    monkeypatch.setattr(subprocess, "run", command)
    with pytest.raises(ValueError, match="does not match"):
        fixture.ensure_image({})
    assert len(calls) == 1 and calls[0][1:3] == ["image", "inspect"]


def test_source_recipe_changes_select_a_different_cache_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = fixture.image_reference()
    recipe = tmp_path / "Dockerfile"
    recipe.write_bytes(fixture.RECIPE.read_bytes() + b"\n# changed build inputs\n")
    monkeypatch.setattr(fixture, "RECIPE", recipe)
    assert fixture.image_reference() != original
