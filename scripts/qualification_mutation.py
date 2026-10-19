"""Shared operation lock versus exclusive permanent fixture retirement.

Parents and their subprocesses may hold shared ownership concurrently. An
exclusive retirement holder cannot commit its marker until all supported
mutations finish; new mutations check the marker after acquiring the same lock.
This is separate from the non-reentrant qualification run lease.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Concatenate

from scripts.qualification_disposition import original_run, require_available, require_environment
from scripts.qualification_fence import lock
from scripts.qualification_fence import ownership as persistent_ownership

LOCK = "fixture-operation.lock"


@contextmanager
def ownership(
    run: Path, *, exclusive: bool = False, fixture_id: str | None = None, create: bool = True
) -> Iterator[None]:
    origin = original_run(run)
    if origin.resolve() != origin or origin.is_symlink():
        raise ValueError("fixture operation root is not canonical")
    with persistent_ownership(origin, exclusive=exclusive, fixture_id=fixture_id, create=create):
        if not origin.exists():
            if not exclusive:
                require_available(run)
            yield
            return
        with lock(origin / LOCK, exclusive=exclusive, create=create):
            if not exclusive:
                require_available(run)
            yield


@contextmanager
def environment_ownership(environment: Mapping[str, str]) -> Iterator[None]:
    require_environment(environment)
    artifact = environment.get("LDP_QUALIFICATION_ARTIFACT")
    if artifact:
        with ownership(Path(artifact).parent.parent):
            yield
    else:
        yield


def protected_run[**P, R](
    function: Callable[Concatenate[Path, P], R],
) -> Callable[Concatenate[Path, P], R]:
    @wraps(function)
    def guarded(run: Path, /, *args: P.args, **kwargs: P.kwargs) -> R:
        with ownership(run):
            return function(run, *args, **kwargs)

    return guarded


def protected_fixture[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
        environment = getattr(args[0], "environment", os.environ)
        with environment_ownership(environment):
            return function(*args, **kwargs)

    return guarded
