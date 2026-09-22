from datetime import datetime, timedelta
from typing import Literal

Reachability = Literal["approved", "online", "stale", "approval_expired"]


def classify_reachability(last_seen: datetime | None, activate_before: datetime | None,
                          observed_at: datetime) -> Reachability:
    """Recent contact takes precedence over the initial activation deadline."""
    if last_seen is not None:
        return "online" if last_seen > observed_at - timedelta(seconds=45) else "stale"
    if activate_before is not None and activate_before <= observed_at:
        return "approval_expired"
    return "approved"
