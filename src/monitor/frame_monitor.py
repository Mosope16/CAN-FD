"""CAN-FD Frame Monitor and Per-ID State Tracker.

Maintains temporal baselines, historical payload buffers, and inter-arrival
tracking for all observed arbitration identifiers.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional
from src.generator.message_definitions import MessageDefinition


class FrameMonitor:
    """Tracks state and history for CAN-FD frames arriving on the bus."""

    def __init__(
        self,
        network_defs: dict[int, MessageDefinition],
        history_buffer_size: int = 1000,
    ) -> None:
        self.network_defs = network_defs
        self.history_buffer_size = history_buffer_size

        # Precompute expected periods in microseconds
        self.expected_periods_us: dict[int, int] = {
            mid: mdef.period_ms * 1000 for mid, mdef in network_defs.items()
        }
        self.configured_dlcs: dict[int, int] = {
            mid: mdef.dlc for mid, mdef in network_defs.items()
        }

        self.last_timestamp_us: dict[int, int] = {}
        self.last_payload: dict[int, bytes] = {}
        self.payload_history: dict[int, deque[bytes]] = {
            mid: deque(maxlen=history_buffer_size) for mid in network_defs
        }
        self.historical_payload_set: dict[int, set[bytes]] = {
            mid: set() for mid in network_defs
        }
        self.recent_buffer_size = 50

    def update_frame(
        self,
        arbitration_id: int,
        timestamp_us: int,
        dlc: int,
        data: bytes,
    ) -> tuple[int, int, int, int, int, int, Optional[bytes]]:
        """Update tracker with newly received frame and return atomic metrics.

        Returns:
            (inter_arrival_us, period_deviation_us, payload_delta,
             payload_change_count, id_seen_before, dlc_mismatch, prev_payload)
        """
        # 1. Check if ID is known from DBC baseline
        id_seen_before = 1 if arbitration_id in self.network_defs else 0

        # 2. Check DLC mismatch
        expected_dlc = self.configured_dlcs.get(arbitration_id)
        dlc_mismatch = 1 if (expected_dlc is not None and expected_dlc != dlc) else 0

        # 3. Inter-arrival and period deviation
        if arbitration_id in self.last_timestamp_us:
            inter_arrival_us = timestamp_us - self.last_timestamp_us[arbitration_id]
        else:
            inter_arrival_us = self.expected_periods_us.get(arbitration_id, 0)

        expected_p = self.expected_periods_us.get(arbitration_id, 0)
        if expected_p > 0:
            period_deviation_us = inter_arrival_us - expected_p
        else:
            period_deviation_us = 0

        # 4. Payload delta and Hamming change count against previous payload
        prev_data = self.last_payload.get(arbitration_id)
        if prev_data is not None and len(prev_data) > 0 and len(data) > 0:
            payload_delta = abs(int(data[0]) - int(prev_data[0]))
            min_len = min(len(data), len(prev_data))
            change_count = sum(1 for i in range(min_len) if data[i] != prev_data[i])
            change_count += abs(len(data) - len(prev_data))
        else:
            payload_delta = 0
            change_count = 0

        # 5. Update state
        self.last_timestamp_us[arbitration_id] = timestamp_us
        self.last_payload[arbitration_id] = data

        if arbitration_id not in self.payload_history:
            self.payload_history[arbitration_id] = deque(maxlen=self.history_buffer_size)
            self.historical_payload_set[arbitration_id] = set()

        q = self.payload_history[arbitration_id]
        if len(q) >= self.recent_buffer_size:
            self.historical_payload_set[arbitration_id].add(q[-self.recent_buffer_size])
            if len(self.historical_payload_set[arbitration_id]) > self.history_buffer_size:
                # Bounded pruning: synchronize set with current deque window to prevent memory bloat
                self.historical_payload_set[arbitration_id] = set(list(q)[:-self.recent_buffer_size])
        q.append(data)

        return (
            inter_arrival_us,
            period_deviation_us,
            payload_delta,
            change_count,
            id_seen_before,
            dlc_mismatch,
            prev_data,
        )
