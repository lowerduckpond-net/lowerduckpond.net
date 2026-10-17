"""Shared live-run ceiling and credential reserve; neither is a runtime estimate."""

from datetime import timedelta

LIVE_SECONDS = 600 * 60
# Detached provisioning, independent confirmation and production checks precede
# the wrapper. Preserve its full budget within the separately bounded attempt.
ATTEMPT_SECONDS = LIVE_SECONDS + 60 * 60
TOKEN_CLEANUP_MARGIN = timedelta(hours=2)
MINIMUM_TOKEN_REMAINING = timedelta(seconds=ATTEMPT_SECONDS) + TOKEN_CLEANUP_MARGIN
