"""Dispatch has no issuance authority and remains confined to protected main."""

from __future__ import annotations

from typing import override

import pytest

from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended.connect_action import WORKFLOW
from scripts.m3_11_unattended.model import LifecycleError


class GitHubDouble(control.GitHub):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.rules: list[dict[str, object]] = [{"type": "branch_policy"}]
        self.branches: list[dict[str, object]] = [{"name": "main", "type": "branch"}]
        self.fail_post = False

    @override
    def api(self, path: str, *, method: str = "GET", body: object = None) -> object:
        self.calls.append((method, path, body))
        if method == "POST":
            if self.fail_post:
                raise LifecycleError("synthetic lost dispatch reply")
            return None
        if path.endswith("/deployment-branch-policies"):
            return {"branch_policies": self.branches}
        return {
            "protection_rules": self.rules,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }


@pytest.mark.parametrize("operation", ["confirm", "cleanup"])
def test_dispatch_is_single_main_request_without_wait_or_acknowledgement(operation: str) -> None:
    client = GitHubDouble()
    client.dispatch(operation)
    assert [call for call in client.calls if call[0] == "POST"] == [
        (
            "POST",
            f"{control.PREFIX}/actions/workflows/{WORKFLOW}/dispatches",
            {"ref": "main", "inputs": {"operation": operation}},
        )
    ]


@pytest.mark.parametrize(
    "fault", ["reviewer", "timer", "branch", "tag", "multiple", "obsolete-operation"]
)
def test_approval_wait_or_unsafe_branch_cannot_dispatch(fault: str) -> None:
    client = GitHubDouble()
    operation = "confirm"
    if fault in {"reviewer", "timer"}:
        client.rules.append({"type": fault})
    elif fault == "branch":
        client.branches[0]["name"] = "*"
    elif fault == "tag":
        client.branches[0]["type"] = "tag"
    elif fault == "multiple":
        client.branches.append({"name": "dev", "type": "branch"})
    else:
        operation = "witness"
    with pytest.raises(LifecycleError):
        client.dispatch(operation)
    assert not any(call[0] == "POST" for call in client.calls)


def test_lost_dispatch_reply_is_not_automatically_repeated() -> None:
    client = GitHubDouble()
    client.fail_post = True
    with pytest.raises(LifecycleError):
        client.dispatch("confirm")
    assert sum(call[0] == "POST" for call in client.calls) == 1
