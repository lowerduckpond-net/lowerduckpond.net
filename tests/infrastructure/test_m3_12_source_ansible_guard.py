"""Exercise the site playbook's Ansible guard with synthetic guest reads and local phase gates."""

from __future__ import annotations

import io
import os
import sys
from collections.abc import Callable
from contextlib import redirect_stdout
from multiprocessing import get_context
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent import droplet_enrollment, source_bootstrap

from infrastructure.test_m3_11_production_gate import publish
from infrastructure.test_m3_12_droplet_journey import fixture as fixture  # noqa: PLC0414
from infrastructure.test_m3_12_droplet_journey import records as records  # noqa: PLC0414
from infrastructure.test_m3_12_source_bootstrap import handoff as handoff  # noqa: PLC0414
from scripts import m3_11_production_gate as production
from scripts import m3_11_production_lease as lease
from scripts import m3_12_droplet_action as source
from scripts import m3_12_source_operator as operator
from scripts.m3_12_contracts import Document, digest, encode
from scripts.m3_12_droplet_ssh import source_argv

PRODUCTION = "ldp_m3_11"
DISPOSABLE = "ldp_m3_12_droplet"
HELPER = "/run/lowerduckpond-m3-11/" + "d" * 64 + ".pyz"
JOURNAL = "/var/lib/lowerduckpond/convergence/m3-11"
SUCCESSOR = "/var/lib/lowerduckpond/convergence/m3-12/transaction.json"
Gate = Callable[[list[str], bytes], str]


def run_guard(  # noqa: PLR0913 - distinct synthetic controller and guest inputs
    directory: Path,
    connection: str,
    variables: Document,
    *,
    environment: dict[str, str],
    stat: dict[str, bool],
    gate: Gate,
) -> tuple[int | None, str]:
    # Import the actual first site pre-task, including its configured stage and file lookups.
    site = yaml.safe_load((operator.CONFIG / "playbooks/site.yml").read_text())[0]
    (directory / "roles").symlink_to(operator.CONFIG / "roles")
    (directory / "tasks").symlink_to(operator.CONFIG / "tasks")
    books = directory / "playbooks"
    books.mkdir()
    book = books / "witness.yml"
    book.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": operator.HOST,
                    "gather_facts": False,
                    "vars": variables
                    | {"ansible_connection": connection, "ansible_ssh_executable": "/bin/false"},
                    "tasks": [site["pre_tasks"][0]],
                }
            ]
        )
    )
    trace = directory / "guest-gate"

    def play() -> None:
        # Ansible has process-global CLI and plugin state. Confine those and the I/O adapter
        # to this child and give Ansible only the synthetic controller environment.
        os.environ.clear()
        os.environ.update(
            {
                "PATH": "/usr/bin:/bin",
                "HOME": str(directory),
                "LANG": "C.UTF-8",
                "ANSIBLE_CONFIG": str(operator.CONFIG / "ansible.cfg"),
                "ANSIBLE_LOCAL_TEMP": str(directory / "tmp"),
                "ANSIBLE_CONNECTION_PLUGINS": str(operator.CONFIG / "plugins/connection"),
                **environment,
            }
        )
        from ansible.cli.playbook import PlaybookCLI  # noqa: PLC0415
        from ansible.plugins.action import ActionBase  # noqa: PLC0415
        from ansible.plugins.loader import connection_loader  # noqa: PLC0415

        def guest(action: ActionBase, **_kwargs: object) -> Document:
            assert action._connection.transport == connection
            args = action._task.args
            if action._task.action == "ansible.builtin.stat":
                return {"stat": {"exists": stat[args["path"]]}}
            assert action._task.action == "ansible.builtin.command"
            try:
                result = gate(args["argv"], args["stdin"].encode())
            except ValueError as error:
                trace.write_text(str(error))
                return {"failed": True, "msg": str(error)}
            trace.write_text(result)
            return {"rc": 0, "stdout": result}

        connection_loader.add_directory(str(operator.CONFIG / "plugins/connection"))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(ActionBase, "_execute_module", guest)
            raise SystemExit(
                PlaybookCLI(["ansible-playbook", "-i", operator.HOST + ",", str(book)]).run()
            )

    process = get_context("fork").Process(target=play)
    process.start()
    process.join()
    return process.exitcode, trace.read_text() if trace.exists() else ""


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("reviewed", "dark-staging"),
        ("stale-token", "production controller was superseded"),
        ("no-token", "production lease token is invalid"),
        ("wrong-host", "droplet-enrollment-changed"),
        ("wrong-stage", "droplet-source-stage-inputs-changed"),
        ("plain-ssh", ""),
        ("missing-predecessor", ""),
        ("production-successor", ""),
    ],
)
def test_disposable_source_guard(  # noqa: PLR0913,PLR0917 - real gate with synthetic host observations
    case: str,
    expected: str,
    handoff: tuple[Document, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    document, _, _ = handoff
    artifact, owner = document["artifactSha256"], os.geteuid()
    path = tmp_path / "runtime" / "lease"
    path.parent.mkdir(mode=0o700)
    path.mkdir(mode=0o700)
    group = tmp_path / "cgroup"
    group.write_text(f"0::/system.slice/{source.UNIT}\n")
    monkeypatch.setattr(source, "CGROUP", group)
    monkeypatch.setattr(source, "LEASE", path)
    source_bootstrap.receive(encode(document), artifact, owner=owner)
    variables = operator._variables(
        {
            "backupNodeName": "fixture",
            "operatorPublicKey": "fixture",
            "operatorPrincipal": "fixture",
        },
        document,
        tmp_path / "artifact",
        [],
        [],
    )
    if case == "wrong-stage":
        variables["static_publication_enabled"] = True
    if case == "wrong-host":
        identity = droplet_enrollment.host_identity(owner) | {"machineSha256": "0" * 64}
        monkeypatch.setattr(droplet_enrollment, "host_identity", lambda _: identity)

    with lease.controller(path, owner=owner, drain=lambda: None) as token:
        receipt = path.parent.joinpath(*source._lease_record(token))
        receipt.write_bytes(encode({"handoffSha256": digest(document)}))
        receipt.chmod(0o600)
        presented = {"stale-token": "e" * 64, "no-token": ""}.get(case, token)

        def gate(argv: list[str], raw: bytes) -> str:
            expected_argv = source_argv(artifact, "gate", presented)
            # The Ansible file lookup strips trailing whitespace from the launcher.
            expected_argv[4] = expected_argv[4].rstrip()
            assert argv == expected_argv
            operation, staged_artifact, *arguments = argv[5:]
            reply = io.StringIO()
            with lease.action(path, owner=owner, token=token), redirect_stdout(reply):
                monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
                assert source.dispatch(staged_artifact, operation, arguments, owner=owner) == 0
            return reply.getvalue().strip()

        status, trace = run_guard(
            tmp_path,
            "ssh" if case == "plain-ssh" else DISPOSABLE,
            variables,
            environment={
                "LDP_M3_12_DROPLET_LEASE_TOKEN": presented,
                "LDP_M3_12_SOURCE_ARTIFACT": artifact,
            },
            stat={
                JOURNAL: case != "missing-predecessor",
                SUCCESSOR: case == "production-successor",
            },
            gate=gate,
        )
    log = capfd.readouterr().out
    assert trace == expected, log
    assert status == (0 if case == "reviewed" else 2), log
    assert "changed=0" in log and "unreachable=0" in log
    if not expected:
        task = {
            "plain-ssh": "Require the leased M3.11 production connection",
            "missing-predecessor": (
                "Require the accepted predecessor and exclude the production successor"
            ),
            "production-successor": "Require the distinct successor configuration connection",
        }[case]
        assert "fatal:" in log.split(f"TASK [{task}]")[1].split("TASK [")[0]


@pytest.mark.parametrize(
    ("phase", "provide_token", "result"),
    [
        ("rotation-enabled.started", True, "rotation-enabled.started"),
        ("accepted", True, "production journal does not authorize configuration"),
        ("rotation-enabled.started", False, ""),
    ],
)
def test_existing_production_guard(  # noqa: PLR0913 - phase and lease matrix
    *,
    phase: str,
    provide_token: bool,
    result: str,
    tmp_path: Path,
    records: list[tuple[str, bytes]],
    capfd: pytest.CaptureFixture[str],
) -> None:
    journal = tmp_path / "m3-11"
    publish(journal, records, phase)
    runtime = tmp_path / "lease"
    runtime.mkdir(mode=0o700)
    owner = os.geteuid()
    with lease.controller(runtime, owner=owner, drain=lambda: None) as token:

        def gate(argv: list[str], raw: bytes) -> str:
            assert argv == ["/usr/bin/python3", "-I", "-B", HELPER, "gate", token]
            with lease.action(runtime, owner=owner, token=token):
                lease.require_action(runtime, owner=owner, token=argv[-1])
                return production.require(journal, raw, owner=owner)

        variables = {
            "static_host_agent_artifact_sha256": "b" * 64,
            "backup_static_recovery_enabled": True,
            "backup_audit_rotation_enabled": True,
            "static_host_agent_archive_lifecycle_enabled": True,
            "caddy_generation_enabled": True,
        }
        status, trace = run_guard(
            tmp_path,
            PRODUCTION,
            variables,
            environment={
                "LDP_M3_11_ACTION_HELPER": HELPER,
                "LDP_M3_11_LEASE_TOKEN": token if provide_token else "",
            },
            stat={JOURNAL: True, SUCCESSOR: False},
            gate=gate,
        )
    log = capfd.readouterr().out
    assert trace == result, log
    assert status == (0 if phase == result else 2), log
    assert "changed=0" in log and "unreachable=0" in log
    if not provide_token:
        task = "Require the leased M3.11 production connection"
        assert "fatal:" in log.split(f"TASK [{task}]")[1].split("TASK [")[0]
