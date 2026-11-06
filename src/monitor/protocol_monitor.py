"""Protocol Error Monitor and Missing Message Deadline Supervisor.

Detects message suppression by evaluating periodic arrival deadlines and
tracks protocol-layer decoding errors across sliding time windows.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set
from src.generator.message_definitions import MessageDefinition


class ProtocolMonitor:
    """Supervises missing frame deadlines and protocol error rates."""

    def __init__(
        self,
        network_defs: dict[int, MessageDefinition],
        deadline_factor: float = 2.5,
        window_duration_us: int = 100_000,  # 100 ms
    ) -> None:
        self.network_defs = network_defs
        self.deadline_factor = deadline_factor
        self.window_duration_us = window_duration_us

        self.expected_periods_us: dict[int, int] = {
            mid: mdef.period_ms * 1000 for mid, mdef in network_defs.items()
        }

        # Last received timestamp per ID
        self.last_seen_us: dict[int, int] = {}
        # Next deadline per ID
        self.next_deadline_us: dict[int, int] = {}

        # Slidings windows for protocol errors and missing frame events
        self.protocol_error_timestamps: deque[int] = deque()
        self.missing_event_timestamps: deque[int] = deque()

    def initialize_deadlines(self, start_time_us: int) -> None:
        """Set initial expected arrival deadlines for all periodic messages."""
        for mid, period_us in self.expected_periods_us.items():
            self.last_seen_us[mid] = start_time_us
            self.next_deadline_us[mid] = start_time_us + int(self.deadline_factor * period_us)

    def record_frame_arrival(self, arbitration_id: int, timestamp_us: int) -> None:
        """Update reception timestamp and advance next expected deadline."""
        self.last_seen_us[arbitration_id] = timestamp_us
        if arbitration_id in self.expected_periods_us:
            period_us = self.expected_periods_us[arbitration_id]
            self.next_deadline_us[arbitration_id] = timestamp_us + int(self.deadline_factor * period_us)

    def record_protocol_error(self, timestamp_us: int) -> None:
        """Log a protocol decoding violation at timestamp_us."""
        self.protocol_error_timestamps.append(timestamp_us)

    def check_deadlines(self, current_time_us: int) -> list[int]:
        """Check all configured periodic IDs for expired deadlines.

        Returns:
            List of CAN IDs whose arrival deadlines have expired.
        """
        expired_ids: list[int] = []
        for mid, deadline_us in list(self.next_deadline_us.items()):
            if current_time_us >= deadline_us:
                expired_ids.append(mid)
                self.missing_event_timestamps.append(current_time_us)
                # Advance next deadline by one period interval to avoid duplicate alert storms
                period_us = self.expected_periods_us.get(mid, 50_000)
                self.next_deadline_us[mid] = deadline_us + period_us
        return expired_ids

    def get_window_counts(self, current_time_us: int) -> tuple[int, int]:
        """Compute counts of protocol errors and missing frames in the active sliding window.

        Returns:
            (protocol_error_count, missing_frame_count)
        """
        cutoff_us = current_time_us - self.window_duration_us

        while self.protocol_error_timestamps and self.protocol_error_timestamps[0] < cutoff_us:
            self.protocol_error_timestamps.popleft()

        while self.missing_event_timestamps and self.missing_event_timestamps[0] < cutoff_us:
            self.missing_event_timestamps.popleft()

        return len(self.protocol_error_timestamps), len(self.missing_event_timestamps)
