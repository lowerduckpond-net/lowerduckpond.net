"""Exercise the real recipes offline; external-report failures use a synthetic tool.

Native Lychee regressions run in the Internal links CI job, which installs both
tools. Python-only environments still run the workflow/report wiring tests.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
Row = dict[str, Any]


def workflow(name: str) -> Row:
    source = (ROOT / ".github/workflows" / name).read_text()
    # BaseLoader preserves GitHub's on key instead of treating it as YAML 1.1 true.
    return cast(Row, yaml.load(source, Loader=yaml.BaseLoader))  # noqa: S506 - scalar-only loader


def run(arguments: list[str], cwd: Path, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - repository commands and disposable synthetic fixtures
        arguments,
        cwd=cwd,
        env={"PATH": os.environ["PATH"], **environment},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.fixture
def recipes(tmp_path: Path) -> Path:
    for name in ("justfile", ".lychee.toml"):
        shutil.copyfile(ROOT / name, tmp_path / name)
    return tmp_path


@pytest.fixture
def native(recipes: Path) -> Path:
    if not all(shutil.which(tool) for tool in ("lychee", "just")):
        pytest.skip("Native regressions run in the Internal links CI job")
    (recipes / "target.md").write_text(
        '# Target\n\n## Valid heading\n\n<a id="explicit-id"></a>\n\n## Repeat\n\n## Repeat\n'
    )
    (recipes / "target.html").write_text('<h1 id="valid-heading">Target</h1>\n')
    (recipes / "source.py").write_text("# One line\n")
    return recipes


@pytest.mark.parametrize(
    ("target", "valid"),
    [
        ("target.md", True),
        ("target.md#valid-heading", True),
        ("target.md#explicit-id", True),
        ("target.md#repeat-1", True),
        ("target.html#valid-heading", True),
        ("#self", True),
        ("missing.md", False),
        ("target.md#missing", False),
        ("target.html#missing", False),
        ("#missing", False),
        # Lychee does not validate line fragments in source files; document this limit.
        ("source.py#L99999", True),
    ],
)
def test_internal_paths_and_supported_anchors(native: Path, target: str, valid: bool) -> None:
    (native / "index.md").write_text(f"# Self\n\n[link]({target})\n")
    result = run(["just", "check-links"], native)
    assert (result.returncode == 0) is valid, result.stdout + result.stderr


def test_internal_recipe_ignores_unavailable_external_urls(native: Path) -> None:
    (native / "index.md").write_text(
        "[HTTP](http://unavailable.lowerduckpond.net/)\n"
        "[HTTPS](https://unavailable.lowerduckpond.net/)\n"
    )
    result = run(["just", "check-links"], native)
    assert result.returncode == 0, result.stdout + result.stderr


def test_external_recipe_selects_only_http_urls_without_requesting_them(native: Path) -> None:
    (native / "index.md").write_text(
        "# Self\n\n[local](missing.md)\n[anchor](#missing)\n"
        "[HTTP](http://github.com/digitalocean/terraform-provider-digitalocean)\n"
        "[HTTPS](https://github.com/caddyserver/certmagic)\n"
        "[mail](mailto:nobody@example.invalid)\n"
        "[excluded](https://docs.min.io/reference)\n"
    )
    recipe = run(["just", "--dry-run", "report-external-links", "report.md"], native)
    assert recipe.returncode == 0, recipe.stderr
    result = run([*shlex.split(recipe.stderr.strip()), "--dump"], native)
    assert result.returncode == 0, result.stdout + result.stderr
    assert set((native / "report.md").read_text().splitlines()) == {
        "http://github.com/digitalocean/terraform-provider-digitalocean",
        "https://github.com/caddyserver/certmagic",
    }


def test_gate_requires_internal_links_and_has_no_external_dependency() -> None:
    ci = workflow("ci.yml")
    links = ci["jobs"]["links"]
    assert "if" not in links and "continue-on-error" not in links
    assert any(step.get("run") == "just check-links" for step in links["steps"])
    assert all("continue-on-error" not in step and "if" not in step for step in links["steps"])
    assert any(
        step.get("with", {}).get("install_args") == "just python uv github:lycheeverse/lychee"
        for step in links["steps"]
    )
    assert any("test_link_checks.py" in step.get("run", "") for step in links["steps"])
    gate = ci["jobs"]["gate"]
    assert "links" in gate["needs"]
    assert all(job in ci["jobs"] for job in gate["needs"])
    assert "report-external-links" not in (ROOT / ".github/workflows/ci.yml").read_text()
    check = next(
        line for line in (ROOT / "justfile").read_text().splitlines() if line.startswith("check:")
    )
    assert "check-links" in check and "report-external-links" not in check


def test_external_report_is_scheduled_and_informational() -> None:
    report = workflow("external-links.yml")
    assert set(report["on"]) == {"schedule"}
    assert report["on"]["schedule"] == [{"cron": "47 5 * * 1"}]
    assert report["permissions"] == {"contents": "read"}
    job = report["jobs"]["report"]
    assert "needs" not in job
    steps = job["steps"]
    check = next(step for step in steps if "report-external-links" in step.get("run", ""))
    assert check["continue-on-error"] == "true"
    summary = next(step for step in steps if "GITHUB_STEP_SUMMARY" in step.get("run", ""))
    assert summary["if"] == "always()"
    artifact = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert artifact["if"] == "always()"
    assert artifact["with"]["path"] == "${{ runner.temp }}/external-links.md"
    assert artifact["with"]["retention-days"] == "30"


@pytest.mark.parametrize("link_result", ["success", "failure", "cancelled", "skipped"])
def test_gate_rejects_unsuccessful_internal_check(tmp_path: Path, link_result: str) -> None:
    gate = workflow("ci.yml")["jobs"]["gate"]
    assert gate["if"] == "always()"
    required = gate["steps"][0]
    assert required["env"]["RESULTS"] == "${{ join(needs.*.result, ',') }}"
    results = ",".join(link_result if name == "links" else "success" for name in gate["needs"])
    result = run(
        ["/bin/bash", "-euo", "pipefail", "-c", required["run"]], tmp_path, RESULTS=results
    )
    assert (result.returncode == 0) is (link_result == "success")


@pytest.mark.parametrize("creates_report", [True, False])
def test_failed_report_is_published_or_marked_unavailable(
    recipes: Path, creates_report: bool
) -> None:
    fake_bin = recipes / "bin"
    fake_bin.mkdir()
    checker = fake_bin / "lychee"
    report_content = "# Links\n\nHTTP 503 findings\n"
    checker.write_text(
        f"#!{sys.executable}\n"
        "import sys\nfrom pathlib import Path\n"
        + (
            f"Path(sys.argv[sys.argv.index('--output') + 1]).write_text({report_content!r})\n"
            if creates_report
            else ""
        )
        + "sys.exit(2)\n"
    )
    checker.chmod(0o700)
    summary = recipes / "summary.md"
    # A space in the report path exercises the actual recipe's quoting.
    temporary = recipes / "runner temp"
    temporary.mkdir()
    environment = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(temporary),
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    steps = workflow("external-links.yml")["jobs"]["report"]["steps"]
    check = next(step for step in steps if "report-external-links" in step.get("run", ""))
    result = run(["/bin/bash", "-euo", "pipefail", "-c", check["run"]], recipes, **environment)
    assert result.returncode != 0
    publish = next(step for step in steps if "GITHUB_STEP_SUMMARY" in step.get("run", ""))
    result = run(["/bin/bash", "-euo", "pipefail", "-c", publish["run"]], recipes, **environment)
    assert result.returncode == 0, result.stderr
    assert "does not gate merges" in summary.read_text()
    if creates_report:
        assert "HTTP 503 findings" in summary.read_text()
        assert "HTTP 503 findings" in (temporary / "external-links.md").read_text()
    else:
        assert "Report unavailable" in summary.read_text()
