"""Terminal local-only disposal; no provider factories, probes or secret delivery.

This owner is deliberately separate from the live-credential remote owner.
The permanent registry and all lease/attempt/controller metadata survive. Only
the exact approved stopped actors, owned image tag and original fixture subtree
can be removed, after full export and terminal lease proof.
"""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import cast

from scripts import m3_11_frozen_actor_export as actor_export
from scripts import m3_11_frozen_capture_resume as capture_resume
from scripts import m3_11_frozen_export as export
from scripts import m3_11_frozen_remote_proof as remote_proof
from scripts.m3_11_frozen_budget import EXPORT_SECONDS, MAX_ENTRIES, MAX_LOCAL_BYTES
from scripts.m3_11_frozen_context import actor, require
from scripts.m3_11_frozen_residual import Residual
from scripts.m3_11_frozen_retirement import require_supported_closeout
from scripts.m3_11_frozen_stage import Effects, authorization, initialize, read_plan
from scripts.m3_11_frozen_terminal_bundle import install as install_terminal
from scripts.m3_11_frozen_terminal_bundle import verify as terminal_proof
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields, uuid7
from scripts.m3_11_retirement_files import CHUNK, digest, directory, record, sync
from scripts.m3_11_unattended.docker import LEASE_DIRECTORY, Docker
from scripts.m3_11_unattended.model import identity
from scripts.m3_11_unattended.state import LeaseState, journey_result
from scripts.m3_11_unattended.storage_admission import existing_lock, require_remaining
from scripts.qualification_context import IMAGE_ENV, resource_names
from scripts.qualification_fence import lock as identity_lock
from scripts.qualification_fence import ownership, registry, require_committed

FORMAT = "lowerduckpond-m3-11-frozen-local-disposal-v1"
ROLES = {"destination", "host", "acme", "archive"}


class LocalDocker(Docker):
    """Fixed daemon surface, never a generic retired-fixture execution bypass."""

    def command(self, *arguments: str, stdin: bytes | None = None, timeout: int = 1200) -> bytes:
        require(stdin is None and bool(arguments), "local disposal daemon input is invalid")
        require(
            arguments[0] in {"info", "inspect", "ps", "context"}
            or arguments[:2] == ("image", "ls"),
            "local disposal attempted a non-read daemon operation",
        )
        require(
            arguments[0] != "context" or arguments[1:2] == ("inspect",),
            "local disposal attempted a context mutation",
        )
        require_remaining(timeout)
        return super().command(*arguments, timeout=timeout)

    def remove_container(self, selected: str) -> None:
        require(re.fullmatch(r"[0-9a-f]{64}", selected), "local disposal container ID is invalid")
        require_remaining(1200)
        # Persistent mounts are rejected, and no volume-removal flag is exposed.
        super().command("container", "rm", selected, timeout=1200)

    def inspect_actor(self, selected: str) -> dict[str, object]:
        require(re.fullmatch(r"[0-9a-f]{64}", selected), "actor evidence ID is invalid")
        raw = json.loads(self.command("inspect", selected))
        require(
            isinstance(raw, list) and len(raw) == 1 and isinstance(raw[0], dict),
            "actor evidence inspect is ambiguous",
        )
        return cast(dict[str, object], raw[0])

    def actor_bytes(
        self, operation: str, selected: str, guard: Callable[[], None]
    ) -> Iterator[bytes]:
        require(
            operation in {"export", "logs"} and re.fullmatch(r"[0-9a-f]{64}", selected),
            "actor evidence operation is invalid",
        )
        require_remaining(EXPORT_SECONDS)
        deadline = time.monotonic() + EXPORT_SECONDS
        arguments = (
            ["container", "export", selected]
            if operation == "export"
            else ["logs", "--timestamps", selected]
        )
        process = subprocess.Popen(  # noqa: S603 - fixed read-only operations, exact native ID
            [self.executable, *arguments],
            env=self.environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if operation == "logs" else subprocess.DEVNULL,
            bufsize=0,
        )
        try:
            if process.stdout is None:
                raise ValueError("actor evidence native stream is unavailable")
            while True:
                guard()
                remaining = deadline - time.monotonic()
                require(remaining > 0, "actor evidence command exceeded its deadline")
                if not select.select([process.stdout], [], [], remaining)[0]:
                    raise TimeoutError("actor evidence read deadline ended")
                block = os.read(process.stdout.fileno(), CHUNK)
                if not block:
                    break
                yield block
            require(
                process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                "actor evidence native command failed",
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()

    def remove_image(self, reference: str, owner: str) -> None:
        require(
            reference == "molecule_local/" + resource_names(owner)[IMAGE_ENV],
            "local disposal image reference differs",
        )
        require_remaining(1200)
        super().command("image", "rm", reference, timeout=1200)


class NativeLocal:
    def __init__(
        self, *, evidence_root: Path, docker: LocalDocker, revalidate_copies: Callable[[], str]
    ) -> None:
        self.root, self.docker, self.revalidate_copies = evidence_root, docker, revalidate_copies
        self.held = False
        self.prepare_capture = False

    def selected(self, raw: object) -> dict[str, object]:
        value = fields(
            raw,
            {
                "format",
                "implementation_revision",
                "retirement_plan",
                "fixture",
                "exclusion",
                "terminal_selection",
                "terminal_capture",
                "remote_directory",
                "remote_receipt_file",
                "remote_receipt_sha256",
                "remote_observation",
                "image",
                "export_directory",
                "maximum_export_bytes",
                "maximum_export_entries",
            },
        )
        from scripts.m3_11_frozen_retirement import plan as parse_plan  # noqa: PLC0415

        self.plan = value
        retired = parse_plan(value["retirement_plan"])
        require(
            value["format"] == FORMAT
            and re.fullmatch(r"[a-f0-9]{40}", str(value["implementation_revision"]))
            and isinstance(value["fixture"], dict)
            and digest(value["fixture"]) == retired["fixture_sha256"],
            "local disposal plan or fixture differs",
        )
        self.retirement = retired
        self.run = Path(str(retired["original_run"]))
        self.producer = self.root / "runs" / identity(retired["producing_attempt"])
        self.consumer = self.root / "runs" / identity(retired["consumer_attempt"])
        self.lease = LeaseState(self.root / "leases" / identity(retired["lease_id"]))
        self.fixture = cast(dict[str, object], value["fixture"])
        self.exclusion = cast(dict[str, object], value["exclusion"])
        self.owner_id = uuid7(self.exclusion["fixture_id"]).hex
        require(
            self.run.parent == self.producer / "qualification"
            and self.run.name.startswith("spaces-"),
            "local disposal escaped its producing fixture",
        )
        root = registry(self.run)
        require(root == self.root / "fixture-dispositions", "local disposal registry differs")
        self.stage_root = (
            cast(Path, root)
            / ("identity-" + self.owner_id + ".retired")
            / ("local-" + digest(value))
        )
        self.export_root = Path(str(value["export_directory"]))
        require(
            self.export_root.is_relative_to(cast(Path, root))
            and not self.export_root.is_relative_to(self.stage_root)
            and self.export_root != cast(Path, root),
            "local disposal export is outside its retained registry scope",
        )
        self.limits = export.Limits(
            cast(int, value["maximum_export_bytes"]), cast(int, value["maximum_export_entries"])
        )
        require(
            self.limits.bytes <= MAX_LOCAL_BYTES and self.limits.entries <= MAX_ENTRIES,
            "local disposal export exceeds bounded scope",
        )
        self.actors = cast(list[dict[str, object]], self.fixture["actors"])
        require(
            bool(self.actors)
            and len(self.actors) <= len(ROLES)
            and len({row["id"] for row in self.actors}) == len(self.actors)
            and all(
                row["owner"] == self.owner_id
                and row["name"] in {f"/ldp-m3-{self.owner_id}-{role}" for role in ROLES}
                and row["running"] is False
                and row["restart_policy"] == "no"
                for row in self.actors
            ),
            "local disposal actors differ from exact stopped fixture ownership",
        )
        self.image = fields(value["image"], {"id", "reference"})
        require(
            self.image["reference"] == "molecule_local/" + resource_names(self.owner_id)[IMAGE_ENV]
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(self.image["id"]))
            and any(
                row["image"] == self.image["id"] and str(row["name"]).endswith("-host")
                for row in self.actors
            ),
            "local disposal image lacks original owned source binding",
        )
        return value

    @contextmanager
    def locked(self) -> Iterator[None]:
        require(not self.held, "local disposal is already holding ownership")
        with ExitStack() as locks:
            locks.enter_context(existing_lock(self.consumer / "controller.lock"))
            locks.enter_context(existing_lock(self.lease.directory / "runtime-use.lock"))
            manifest = self.lease.manifest()
            require(
                manifest.sha256 == self.retirement["manifest_sha256"],
                "local disposal lease manifest differs",
            )
            target = {
                "region": manifest.targets.region,
                "archive_bucket": manifest.targets.archive_bucket,
            }
            locks.enter_context(existing_lock(Path(LEASE_DIRECTORY) / (digest(target) + ".lock")))
            # These external locks were durably created before retirement. The
            # fixture's internal lock files are exported/removable evidence and
            # cannot be required or recreated during partial-tree continuation.
            locks.enter_context(
                ownership(
                    self.run,
                    exclusive=True,
                    fixture_id=str(self.exclusion["fixture_id"]),
                    create=False,
                )
            )
            require_committed(self.run, self.exclusion)
            require(
                self.exclusion.get("plan_sha256") == digest(self.retirement)
                and self.exclusion.get("original_run") == str(self.run),
                "local disposal exclusion binding differs",
            )
            if self.prepare_capture:
                install_terminal(
                    self.plan["terminal_selection"],
                    self.plan["terminal_capture"],
                    registry=self.root / "fixture-dispositions",
                )
            self.terminal = terminal_proof(self.plan["terminal_selection"], self.lease)
            self.uses = {
                path.name: read_private(path)
                for path in sorted(self.lease.directory.glob("use-*.json"))
            }
            require(bool(self.uses), "local disposal lacks original runtime-use inventory")
            self.releases = {}
            all_owners: set[str] = set()
            for use in self.uses.values():
                attempt = identity(use["attempt_id"])
                require(
                    self.lease.released_use(
                        attempt_id=attempt, binding_sha256=str(use["binding_sha256"])
                    ),
                    "local disposal requires all original consumers released",
                )
                release = read_private(self.lease.directory / ("released-" + attempt + ".json"))
                self.releases[attempt] = release
                proof = cast(dict[str, object], release["quiescence"])
                all_owners.update(
                    str(row["owner"]) for row in cast(list[dict[str, object]], proof["containers"])
                )
                if "owner" in proof:
                    all_owners.add(str(proof["owner"]))
            for owner in sorted(all_owners - {self.owner_id}):
                uuid7(str(uuid.UUID(hex=owner)))
                locks.enter_context(
                    identity_lock(
                        self.root / "fixture-dispositions" / ("identity-" + owner + ".lock"),
                        exclusive=True,
                        create=self.prepare_capture,
                    )
                )
            self.removed: set[str] = set()
            self.prior_disposals: dict[str, dict[str, object]] = {}
            self.held = True
            try:
                yield
            finally:
                self.held = False

    def copy_guard(self) -> None:
        """Fast local fence under held locks; no daemon/provider request per chunk."""
        require(self.held, "local disposal lacks exclusive ownership")
        require_remaining(60)
        require_committed(self.run, self.exclusion)

    def owner(self) -> None:
        self.copy_guard()
        require(
            {
                path.name: read_private(path)
                for path in sorted(self.lease.directory.glob("use-*.json"))
            }
            == self.uses,
            "local disposal runtime consumer inventory changed",
        )
        daemon = self.docker.info()
        for use in self.uses.values():
            attempt = identity(use["attempt_id"])
            require(
                self.lease.released_use(
                    attempt_id=attempt, binding_sha256=str(use["binding_sha256"])
                ),
                "local disposal requires verified release of every consumer",
            )
            root = self.root / "runs" / attempt
            request = read_private(root / "request.json")
            require(
                digest(request["binding"]) == use["binding_sha256"]
                and request["lease_id"] == self.retirement["lease_id"]
                and request["daemon"] == daemon,
                "local disposal consumer binding or daemon differs",
            )
            journey_result(root)
            require(
                read_private(self.lease.directory / ("released-" + attempt + ".json"))
                == self.releases[attempt],
                "local disposal original release evidence changed",
            )
        # No status.closure == complete requirement: original failed qualification
        # remains unresolved, independently of terminal credential cleanup.

    def inventory(self, removed: set[str]) -> None:
        self.owner()
        self.consumers(removed)
        expected = {str(row["id"]): row for row in self.actors if row["id"] not in removed}
        ids = set()
        for selector in (
            "label=lowerduckpond.qualification.run=" + self.owner_id,
            f"name=^/ldp-m3-{self.owner_id}-({'|'.join(sorted(ROLES))})$",
        ):
            rows = (
                self.docker.command(
                    "ps", "--all", "--no-trunc", "--filter", selector, "--format", "{{.ID}}"
                )
                .decode()
                .splitlines()
            )
            require(len(rows) == len(set(rows)), "local disposal daemon inventory repeats an actor")
            ids.update(rows)
        require(ids == set(expected), "local disposal actor inventory changed")
        for selected in sorted(ids):
            raw = json.loads(self.docker.command("inspect", selected))
            require(
                isinstance(raw, list)
                and len(raw) == 1
                and actor(raw[0]) == expected[selected]
                and raw[0]["State"]["Pid"] == 0,
                "local disposal actor resumed or changed",
            )
            if str(expected[selected]["name"]).endswith("-host"):
                row = raw[0]
                require(
                    {
                        "id": row["Id"],
                        "started": row["State"]["StartedAt"],
                        "finished": row["State"]["FinishedAt"],
                        "restarts": row["RestartCount"],
                    }
                    == self.fixture["source_incarnation"],
                    "local disposal source changed since state preservation",
                )

    def image_present(self) -> bool:
        self.owner()
        actual = (
            self.docker.command(
                "image",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "reference=" + str(self.image["reference"]),
                "--format",
                "{{.ID}}",
            )
            .decode()
            .strip()
        )
        require(actual in {"", self.image["id"]}, "local disposal owned image tag was replaced")
        return bool(actual)

    def prerequisites(self) -> None:
        self.owner()
        self.inventory(set())
        require(self.image_present(), "local disposal owned image is unexpectedly absent")
        self.remote_evidence()

    def remote_evidence(self, preserved: dict[str, object] | None = None) -> None:
        require(
            self.revalidate_copies() == self.retirement["evidence_sha256"],
            "local disposal preserved archive/state validation differs",
        )
        remote = Path(str(self.plan["remote_directory"]))
        directory(remote)
        filename = str(self.plan["remote_receipt_file"])
        require(
            filename == "completed.json"
            or re.fullmatch(r"observation-[a-f0-9]{64}.json", filename),
            "local disposal remote receipt filename is invalid",
        )
        supplied = self.plan["remote_observation"]
        require(
            supplied is None
            if filename == "completed.json"
            else isinstance(supplied, dict)
            and filename == "observation-" + digest(supplied) + ".json",
            "local disposal observation transfer differs from its approved exact bytes",
        )
        path = remote / filename
        publish = not path.exists() and not path.is_symlink()
        if publish:
            require(
                self.prepare_capture and isinstance(supplied, dict),
                "read-only observation cannot materialize missing remote evidence",
            )
            receipt = cast(dict[str, object], supplied)
        else:
            receipt = read_private(path)
            require(
                supplied is None or receipt == supplied,
                "local disposal observation differs from original materialization",
            )
        require(
            digest(receipt) == self.plan["remote_receipt_sha256"],
            "local disposal remote evidence file binding differs",
        )
        from scripts.m3_11_frozen_certificate import saved_document  # noqa: PLC0415

        verified = remote_proof.verify(
            self.run,
            self.retirement,
            self.fixture,
            self.lease.manifest(),
            remote,
            receipt,
            guard=self.copy_guard,
            original_storage=None
            if preserved is None
            else saved_document(preserved, self.export_root, "live-storage.json"),
            fixture_id=None if preserved is None else str(self.exclusion["fixture_id"]),
        )
        if publish:
            # Exact separate local-disposal authority covers this append-only
            # observation import. Complete offline original-journal/copy proof
            # above precedes publication. No ACK or provider request is made.
            self.copy_guard()
            record(path, receipt)
            require(read_private(path) == receipt, "remote observation publication reread differs")
        self.remote = verified

    def consumers(self, removed: set[str]) -> None:
        """Terminal-only view; ordinary active-lease admission remains strict."""
        from scripts.m3_11_frozen_certificate import verify_absent  # noqa: PLC0415

        own = {str(row["id"]): row for row in self.actors}
        for attempt, release in self.releases.items():
            proof = cast(dict[str, object], release["quiescence"])
            rows = cast(list[dict[str, object]], proof["containers"])
            owners = {str(row["owner"]) for row in rows}
            if "owner" in proof:
                require(
                    proof["endpoint"] == self.docker.endpoint,
                    "released allocation endpoint differs",
                )
                owners.add(str(proof["owner"]))
            for owner in owners:
                expected = {str(row["id"]): row for row in rows if row["owner"] == owner}
                values: set[str] = set()
                selectors = {"label=lowerduckpond.qualification.run=" + owner}
                selectors.update("id=" + selected for selected in expected)
                selectors.update(
                    "name=^" + re.escape(str(row["name"])) + "$" for row in expected.values()
                )
                for selector in sorted(selectors):
                    found = (
                        self.docker.command(
                            "ps", "--all", "--no-trunc", "--filter", selector, "--format", "{{.ID}}"
                        )
                        .decode()
                        .splitlines()
                    )
                    require(
                        len(found) == len(set(found)),
                        "terminal consumer inventory repeats an actor",
                    )
                    values.update(found)
                if owner != self.owner_id and expected and not values:
                    require(
                        not self.docker.command(
                            "image",
                            "ls",
                            "--all",
                            "--no-trunc",
                            "--filter",
                            "reference=molecule_local/" + resource_names(owner)[IMAGE_ENV],
                            "--format",
                            "{{.ID}}",
                        ).strip(),
                        "disposed terminal consumer image reappeared",
                    )
                    if owner not in self.prior_disposals:
                        self.prior_disposals[owner] = verify_absent(
                            self.root, self.lease, attempt, release, owner, guard=self.copy_guard
                        )
                    continue
                require(values == set(expected) - removed, "terminal consumer inventory changed")
                for selected, row in expected.items():
                    if selected in removed:
                        require(
                            own.get(selected) == row
                            and self.effects.submitted("remove-container-" + selected, row),
                            "terminal consumer absence lacks this exact disposal intent",
                        )
                    else:
                        actual = self.docker.inspect_actor(selected)
                        require(
                            actor(actual) == row
                            and cast(dict[str, object], actual["State"]).get("Pid") == 0,
                            "released terminal consumer resumed or changed",
                        )

    def execute(self, raw: object, approved: object) -> dict[str, object]:
        require_supported_closeout()
        self.selected(raw)
        self.prepare_capture = True
        approval = authorization(approved, self.plan, stage="local-disposal")
        with self.locked():
            self.prerequisites()
            initialize(self.stage_root, self.plan, approval)
            self.effects = Effects(self.stage_root, plan=self.plan, approval=approval)
            preserved, actor_copies = self.capture_copies(continuing=False)
            return self.finish(approval, preserved, actor_copies, observe_only=False)

    def capture_copies(
        self, *, continuing: bool
    ) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
        self.prerequisites()
        actor_root = self.stage_root / "actors"
        actor_root.mkdir(mode=0o700, exist_ok=True)
        directory(actor_root)
        sync(self.stage_root)
        actor_copies = {}
        used_bytes = 0
        for row in self.actors:
            self.inventory(set())
            selected = str(row["id"])
            maximum = self.limits.bytes - used_bytes

            def check(
                row: dict[str, object] = row, selected: str = selected, maximum: int = maximum
            ) -> dict[str, object]:
                return actor_export.verify(
                    actor_root / selected,
                    row,
                    maximum_bytes=maximum,
                    maximum_entries=self.limits.entries,
                    guard=self.copy_guard,
                )

            def create(
                row: dict[str, object] = row, selected: str = selected, maximum: int = maximum
            ) -> dict[str, object]:
                return actor_export.capture(
                    self.docker,
                    row,
                    actor_root / selected,
                    maximum_bytes=maximum,
                    maximum_entries=self.limits.entries,
                    guard=self.copy_guard,
                )

            actor_copies[selected] = capture_resume.capture(
                actor_root / selected,
                ledger=self.stage_root,
                verify=check,
                create=create,
                guard=self.copy_guard,
                continuing=continuing,
            )
            used_bytes += sum(
                cast(int, cast(dict[str, object], actor_copies[selected][key])["size"])
                for key in ("rootfs", "logs")
            )
        remaining = export.Limits(self.limits.bytes - used_bytes, self.limits.entries)
        capture_resume.capture(
            self.export_root,
            ledger=self.stage_root,
            verify=lambda: export.verify(
                self.run, self.export_root, limits=remaining, guard=self.copy_guard
            ),
            create=lambda: export.preserve(
                self.run, self.export_root, limits=remaining, guard=self.copy_guard
            ),
            guard=self.copy_guard,
            continuing=continuing,
        )
        self.prerequisites()
        return self.retained_copies()

    def retained_copies(self) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
        preserved = export.verify_preserved(
            self.export_root, limits=self.limits, guard=self.copy_guard
        )
        require(
            preserved["root"] == str(self.run), "local continuation export belongs to another root"
        )
        copies = {}
        total = cast(int, preserved["bytes"])
        for row in self.actors:
            selected = str(row["id"])
            copies[selected] = actor_export.verify(
                self.stage_root / "actors" / selected,
                row,
                maximum_bytes=self.limits.bytes,
                maximum_entries=self.limits.entries,
                guard=self.copy_guard,
            )
            total += sum(
                cast(int, cast(dict[str, object], copies[selected][key])["size"])
                for key in ("rootfs", "logs")
            )
        require(total <= self.limits.bytes, "local continuation full exports exceed approved bound")
        return preserved, copies

    def progress(
        self, residual: Residual
    ) -> tuple[set[str], list[str], bool, dict[str, list[str]]]:
        self.owner()
        removed: set[str] = set()
        pending: list[str] = []
        for row in self.actors:
            selected = str(row["id"])
            present = (
                self.docker.command(
                    "ps", "--all", "--no-trunc", "--filter", "id=" + selected, "--format", "{{.ID}}"
                )
                .decode()
                .splitlines()
            )
            require(present in ([], [selected]), "local continuation original ID lookup differs")
            submitted = self.effects.submitted("remove-container-" + selected, row)
            if not present:
                require(submitted, "local actor absence lacks its original exact submission")
                removed.add(selected)
            elif submitted:
                pending.append("remove-container-" + selected)
        self.inventory(removed)
        image_present = self.image_present()
        image_sent = self.effects.submitted("remove-image", self.image)
        if image_present and image_sent:
            pending.append("remove-image")
        elif not image_present:
            require(image_sent, "local image absence lacks its original exact submission")
        tree = residual.observe()
        pending.extend("entry:" + path for path in tree["pending"])
        return removed, pending, image_present, tree

    def finish(
        self,
        approved: dict[str, object],
        preserved: dict[str, object],
        copies: dict[str, dict[str, object]],
        *,
        observe_only: bool,
    ) -> dict[str, object]:
        residual = Residual(self.run, preserved, self.effects, self.copy_guard)
        removed, pending, image_present, tree = self.progress(residual)
        result = {
            "format": FORMAT,
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(approved),
            "export_sha256": digest(preserved),
            "terminal_proof_sha256": digest(self.terminal),
            "remote_proof_sha256": digest(self.remote),
            "actor_exports": {key: digest(value) for key, value in copies.items()},
            "fixture_execution": "permanently-excluded",
            "provider_calls": 0,
            "qualification_changed": False,
            "lease_changed": False,
            "original_directory": "absent",
        }
        completed = self.stage_root / "completed.json"
        recorded = completed.exists() or completed.is_symlink()
        if recorded:
            require(
                read_private(completed) == result
                and not pending
                and not image_present
                and not tree["unsubmitted"]
                and len(removed) == len(self.actors),
                "local recorded completion differs from exact current proofs/resources",
            )
        if observe_only:
            return {
                "format": FORMAT,
                "plan_sha256": digest(self.plan),
                "authorization_sha256": digest(approved),
                "removed_actor_ids": sorted(removed),
                "image_present": image_present,
                "tree": tree,
                "pending_effects": pending,
                "provider_calls": 0,
                "mutation_submissions": 0,
                "no_replay": True,
                "completion_recorded": recorded,
                "export_sha256": digest(preserved),
                "terminal_proof_sha256": digest(self.terminal),
                "remote_proof_sha256": digest(self.remote),
                "actor_exports": {key: digest(value) for key, value in copies.items()},
                "fixture_execution": "permanently-excluded",
            }
        require(not pending, "local submitted effects remain unresolved; no replay")
        for row in self.actors:
            selected = str(row["id"])
            if selected in removed:
                continue

            def remove_actor(selected: str = selected) -> None:
                self.inventory(removed)
                self.docker.remove_container(selected)

            self.effects.submit("remove-container-" + selected, row, remove_actor)
            removed.add(selected)
            self.inventory(removed)
        if image_present:

            def remove_image() -> None:
                self.inventory(removed)
                require(self.image_present(), "local disposal image changed before submission")
                self.docker.remove_image(str(self.image["reference"]), self.owner_id)

            self.effects.submit("remove-image", self.image, remove_image)
        require(not self.image_present(), "local disposal image remains after removal")
        self.inventory(removed)
        residual.remove_unsubmitted()
        self.inventory(removed)
        require(not self.image_present(), "local disposal image reappeared")
        require_committed(self.run, self.exclusion)
        record(self.stage_root / "completed.json", result)
        from scripts.m3_11_frozen_certificate import publish  # noqa: PLC0415

        publish(self, result)
        return result

    def reconcile(
        self, raw: object, approved: object, *, continue_unsubmitted: bool = False
    ) -> dict[str, object]:
        if continue_unsubmitted:
            require_supported_closeout()
        self.selected(raw)
        self.prepare_capture = continue_unsubmitted
        approval = authorization(approved, self.plan, stage="local-disposal")
        with self.locked():
            if continue_unsubmitted:
                initialize(self.stage_root, self.plan, approval, continuing=True)
            require(
                read_plan(self.stage_root) == self.plan
                and read_private(self.stage_root / "authorization.json") == approval,
                "local observation lacks original exact plan and authority",
            )
            self.effects = Effects(self.stage_root, plan=self.plan, approval=approval)
            if continue_unsubmitted and not list(self.stage_root.glob("*.submitted.json")):
                preserved, copies = self.capture_copies(continuing=True)
            else:
                preserved, copies = self.retained_copies()
            self.remote_evidence(preserved)
            return self.finish(approval, preserved, copies, observe_only=not continue_unsubmitted)
