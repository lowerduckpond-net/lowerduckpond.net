"""Shared operation lock versus exclusive permanent fixture retirement.

Parents and their subprocesses may hold shared ownership concurrently. An
exclusive retirement holder cannot commit its marker until all supported
mutations finish; new mutations check the marker after acquiring the same lock.
This is separate from the non-reentrant qualification run lease.
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Concatenate

from scripts.qualification_disposition import original_run, require_available, require_environment

LOCK = "fixture-operation.lock"


@contextmanager
def ownership(run: Path, *, exclusive: bool = False) -> Iterator[None]:
    origin = original_run(run)
    if origin.resolve(strict=True) != origin or not origin.is_dir():
        raise ValueError("fixture operation root is not canonical")
    path = origin / LOCK
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600  # noqa: PLR2004 - private lock
            or before.st_nlink != 1
        ):
            raise ValueError("fixture operation lock is unsafe")
        fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        current = path.lstat()
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("fixture operation lock changed during acquisition")
        if not exclusive:
            require_available(run)
        yield
    finally:
        os.close(descriptor)


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
        if run.exists():
            with ownership(run):
                return function(run, *args, **kwargs)
        # A completely removed directory has no fixture that can be retired;
        # only the existing disposal-receipt finalization may reach this branch.
        return function(run, *args, **kwargs)

    return guarded


def protected_fixture[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
        environment = getattr(args[0], "environment", os.environ)
        with environment_ownership(environment):
            return function(*args, **kwargs)

    return guarded
