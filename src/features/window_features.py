"""Sliding-Window Temporal Rate and Replay Similarity Aggregator.

Maintains time-windowed queues to calculate per-ID transmission rates,
total bus load, duplicate payload occurrences, and historical similarity indices.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Tuple


class SlidingWindowAggregator:
    """Computes temporal sliding-window metrics using integer timestamps."""

    def __init__(
        self,
        window_duration_us: int = 50_000,  # 50 ms default window
    ) -> None:
        self.window_duration_us = window_duration_us
        self.bus_timestamps: deque[int] = deque()
        self.id_timestamps: dict[int, deque[int]] = {}

    def add_frame(self, arbitration_id: int, timestamp_us: int) -> tuple[int, int]:
        """Record frame arrival and return (id_rate, total_bus_rate) in current window."""
        cutoff_us = timestamp_us - self.window_duration_us

        # Add to total bus queue and prune
        self.bus_timestamps.append(timestamp_us)
        while self.bus_timestamps and self.bus_timestamps[0] < cutoff_us:
            self.bus_timestamps.popleft()

        # Add to per-ID queue and prune
        if arbitration_id not in self.id_timestamps:
            self.id_timestamps[arbitration_id] = deque()
        q = self.id_timestamps[arbitration_id]
        q.append(timestamp_us)
        while q and q[0] < cutoff_us:
            q.popleft()

        return len(q), len(self.bus_timestamps)

    @staticmethod
    def compute_replay_metrics(
        current_payload: bytes,
        historical_set: set[bytes],
        prev_payload: Optional[bytes] = None,
    ) -> tuple[int, int]:
        """Compute integer duplicate count and historical replay similarity (0-1000) in O(1) time.

        Returns:
            (replay_similarity, duplicate_count)
        """
        if not current_payload:
            return 0, 0

        # O(1) membership check in historical set
        # Replay indicates matching historical telemetry while differing from immediate predecessor
        # (Matching immediate predecessor represents standard signal continuity, e.g. brake=0%)
        is_continuity = (prev_payload is not None and current_payload == prev_payload)
        if (not is_continuity) and (current_payload in historical_set):
            return 1000, 1

        # Otherwise calculate byte similarity to immediate previous frame
        if prev_payload is not None and len(prev_payload) > 0:
            cur_len = len(current_payload)
            min_len = min(cur_len, len(prev_payload))
            matching = sum(1 for i in range(min_len) if current_payload[i] == prev_payload[i])
            sim = int((matching * 1000) // max(cur_len, len(prev_payload)))
            return sim, 0

        return 0, 0
