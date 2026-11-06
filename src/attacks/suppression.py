"""Message Suppression Attack Engine.

Simulates targeted ECU silencing or bus-off forcing, preventing expected
periodic control telemetry from arriving on the bus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Set


@dataclass
class SuppressionWindow:
    """Defines a time interval during which a specific CAN ID is suppressed."""

    target_id: int
    start_us: int
    end_us: int
    name: str = "Suppression"

    def is_active(self, timestamp_us: int) -> bool:
        return self.start_us <= timestamp_us < self.end_us


class SuppressionAttack:
    """Manages suppression attack schedules across the simulation timeline."""

    def __init__(
        self,
        target_id: int,
        start_ms: int,
        duration_ms: int,
    ) -> None:
        self.target_id = target_id
        self.start_us = start_ms * 1000
        self.end_us = (start_ms + duration_ms) * 1000
        self.window = SuppressionWindow(
            target_id=target_id,
            start_us=self.start_us,
            end_us=self.end_us,
            name=f"Suppression_{hex(target_id)}",
        )

    def is_suppressed(self, target_id: int, timestamp_us: int) -> bool:
        """Check whether target_id is suppressed at timestamp_us."""
        if target_id == self.target_id:
            return self.window.is_active(timestamp_us)
        return False
