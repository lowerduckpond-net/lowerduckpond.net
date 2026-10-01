"""Shared live-run ceiling and credential reserve; neither is a runtime estimate."""

from datetime import timedelta

LIVE_SECONDS = 600 * 60
TOKEN_CLEANUP_MARGIN = timedelta(hours=2)
MINIMUM_TOKEN_REMAINING = timedelta(seconds=LIVE_SECONDS) + TOKEN_CLEANUP_MARGIN
