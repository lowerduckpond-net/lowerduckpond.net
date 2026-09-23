from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import qualification_selection as policy

ROOT = Path(__file__).resolve().parents[2]
GIT = shutil.which("git")
LEAF = "packages/static-host-agent/src/lowerduckpond_static_host_agent/emergency_plan.py"


def command(repository: Path, *arguments: str) -> str:
    assert GIT is not None
    result = subprocess.run(  # noqa: S603 - private fixture repository and fixed git executable
        [GIT, *arguments],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
        timeout=15,
    )
    return result.stdout.strip()


def commit(repository: Path) -> str:
    command(repository, "add", "--all")
    command(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        "fixture",
    )
    return command(repository, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    command(tmp_path, "init", "--quiet")
    for name in (
        LEAF,
        "docs/operations/example.md",
        "packages/static-host-agent/tests/test_emergency_delete.py",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("baseline\n")
    base = commit(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path, base


@pytest.mark.parametrize("kind", ["documentation", "narrow-runtime", "shared-boundary", "unknown"])
def test_representative_comparison_with_previous_selector(
    repository: tuple[Path, str], kind: str
) -> None:
    root, base = repository
    path = {
        "documentation": "docs/operations/example.md",
        "narrow-runtime": LEAF,
        "shared-boundary": (
            "packages/static-host-agent/src/lowerduckpond_static_host_agent/correlations.py"
        ),
        "unknown": "new-unknown-surface.py",
    }[kind]
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("changed\n")
    head = commit(root)
    result = policy.select_revisions(base, head)
    expected = (
        []
        if kind == "documentation"
        else list(policy._EMERGENCY)
        if kind == "narrow-runtime"
        else list(policy.ALL)
    )
    assert isinstance(result["cases"], list)
    assert set(result["cases"]) == set(expected)
    old = subprocess.run(  # noqa: S603 - read-only prior selector on the same fixture commits
        [str(ROOT / "scripts/m3-8-ci-required"), base, head],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
        timeout=15,
    )
    assert old.stdout.strip() == (
        "true" if kind in {"narrow-runtime", "shared-boundary"} else "false"
    )


@pytest.mark.parametrize(
    "kind",
    [
        "rename-into-docs",
        "rename-out-of-docs",
        "delete-code",
        "delete-docs",
        "executable-docs",
        "symlink-docs",
        "new-docs",
        "newline-name",
    ],
)
def test_real_git_modes_deletions_and_both_rename_sides(
    repository: tuple[Path, str], kind: str
) -> None:
    root, base = repository
    source = root / LEAF
    document = root / "docs/operations/example.md"
    if kind == "rename-into-docs":
        source.rename(root / "docs/renamed.md")
    elif kind == "rename-out-of-docs":
        document.rename(root / "executable-input.py")
    elif kind == "delete-code":
        source.unlink()
    elif kind == "delete-docs":
        document.unlink()
    elif kind == "executable-docs":
        document.chmod(0o755)
    elif kind == "symlink-docs":
        document.unlink()
        document.symlink_to("../../" + LEAF)
    elif kind == "new-docs":
        (root / "docs/new.md").write_text("new\n")
    else:
        (root / "docs/new\nname.md").write_text("new\n")
    result = policy.select_revisions(base, commit(root))
    assert result["mode"] == ("none" if kind in {"delete-docs", "new-docs"} else "all")


@pytest.mark.parametrize("kind", ["missing", "invalid", "empty", "shallow", "timeout", "bad-diff"])
def test_unavailable_metadata_selects_the_complete_matrix(
    repository: tuple[Path, str], monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    _, base = repository
    head = base
    original = policy.git
    if kind == "missing":
        base = "0" * 40
    elif kind == "invalid":
        base = "--arbitrary-option"
    else:

        def git(*arguments: str) -> bytes:
            if kind == "timeout":
                raise subprocess.TimeoutExpired("git", 15)
            if kind == "shallow" and arguments[0] == "rev-parse":
                return b"true\n"
            if kind == "bad-diff" and arguments[0] == "diff":
                return b"malformed\0"
            return original(*arguments)

        monkeypatch.setattr(policy, "git", git)
    assert policy.select_revisions(base, head)["cases"] == list(policy.ALL)


def test_mapping_covers_only_existing_leaf_test_modules() -> None:
    tests = ROOT / "config/ansible/molecule/m3_8/tests"
    mapped = {Path(path).stem for path in policy.DEPENDENCIES if path.startswith(policy._TESTS)}
    consumers = []
    for path in tests.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            imports = (
                [node.module]
                if isinstance(node, ast.ImportFrom)
                else [item.name for item in node.names]
                if isinstance(node, ast.Import)
                else []
            )
            if any(name in mapped for name in imports):
                consumers.append(path.name)
    assert not consumers, "a mapped leaf gained a consumer; update the reviewed group map"
    assert all((ROOT / path).is_file() for path in policy.DEPENDENCIES)
    assert all(set(cases) <= set(policy.ALL) for cases in policy.DEPENDENCIES.values())


def test_narrow_runtime_plan_has_only_the_reviewed_emergency_consumers() -> None:
    package = ROOT / "packages/static-host-agent/src/lowerduckpond_static_host_agent"
    consumers = []
    for path in package.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "lowerduckpond_static_host_agent.emergency_plan"
            ):
                consumers.append(path.name)  # noqa: PERF401 - retain import-site diagnostics
    assert sorted(consumers) == ["emergency_delete.py", "host_restore_emergency.py"]
    assert {"restore-reconstruction", "restore-negative", "restore-tls-bootstrap"} <= set(
        policy._EMERGENCY
    )


def test_all_changed_paths_contribute_and_unknown_dominates() -> None:
    mapped = policy._TESTS + "test_core_independent.py"
    changes = [policy.Change((path,), ("100644", "100644"), "M") for path in (LEAF, mapped)]
    result = policy.select_changes(changes)
    assert isinstance(result["cases"], list)
    assert set(result["cases"]) == {*policy._EMERGENCY, "core"}
    changes.append(policy.Change(("unknown.py",), ("100644", "100644"), "M"))
    assert policy.select_changes(changes)["cases"] == list(policy.ALL)


@pytest.mark.parametrize(
    "raw", [b"missing-terminator", b"unknown\0", b"x" * (policy.MAX_DIFF_BYTES + 1)]
)
def test_malformed_or_oversized_diff_cannot_exempt_checks(raw: bytes) -> None:
    with pytest.raises(ValueError):
        policy.parse_changes(raw)
