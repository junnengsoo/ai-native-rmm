"""Deterministic boundaries for the device reachability policy."""
from datetime import datetime, timedelta, timezone

import pytest

from control_plane.reachability import classify_reachability


@pytest.mark.parametrize(("last_seen_age", "activation_remaining", "expected"), [
    (None, 1, "awaiting_activation"),
    (None, 0, "activation_expired"),
    (None, -1, "activation_expired"),
    (None, None, "awaiting_activation"),
    (44.999999, -1, "online"),
    (45, 1, "stale"),
    (45.000001, -1, "stale"),
])
def test_reachability_boundaries(last_seen_age, activation_remaining, expected):
    observed_at = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
    last_seen = None if last_seen_age is None else observed_at - timedelta(seconds=last_seen_age)
    activate_before = None if activation_remaining is None else observed_at + timedelta(seconds=activation_remaining)
    assert classify_reachability(last_seen, activate_before, observed_at) == expected
