"""Deterministic CAN-FD Traffic Generator.

Schedules and generates periodic and event-driven CAN-FD frames conforming to
network configuration and physical signal dynamics.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set
import random

from src.generator.message_definitions import (
    MessageDefinition,
    dlc_to_bytes,
    load_network_config,
)
from src.generator.signal_generator import SignalGenerator


@dataclass
class CANFDFrame:
    """Represents a logical CAN-FD transmission frame."""

    timestamp_us: int
    arbitration_id: int
    dlc: int
    data: bytes
    is_extended: bool = False
    brs: bool = True
    esi: bool = False
    label: int = 0  # 0: Normal, 1: DoS, 2: Fuzzing, 3: Spoofing, 4: Replay, 5: Suppression
    attack_name: str = "Normal"

    @property
    def payload_bytes(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict:
        return {
            "timestamp_us": self.timestamp_us,
            "arbitration_id": hex(self.arbitration_id),
            "dlc": self.dlc,
            "payload_len": len(self.data),
            "data_hex": self.data.hex(),
            "is_extended": self.is_extended,
            "brs": self.brs,
            "esi": self.esi,
            "label": self.label,
            "attack_name": self.attack_name,
        }


@dataclass(order=True)
class ScheduledMessage:
    """Event wrapper for the discrete event priority queue."""

    scheduled_time_us: int
    message_id: int = field(compare=False)


class TrafficGenerator:
    """Generates continuous stream of legitimate CAN-FD traffic."""

    def __init__(
        self,
        network_config_path: str,
        seed: int = 42,
    ) -> None:
        self.message_defs = load_network_config(network_config_path)
        self.signal_gen = SignalGenerator(seed=seed)
        self.rng = random.Random(seed)
        self.seed = seed
        self.suppressed_ids: set[int] = set()

    def set_suppressed_ids(self, ids: set[int]) -> None:
        """Dynamically update IDs currently suppressed by an active attack."""
        self.suppressed_ids = set(ids)

    def generate_trace(
        self,
        duration_ms: int,
        start_time_us: int = 0,
        suppression_hooks: Optional[Callable[[int], set[int]]] = None,
    ) -> list[CANFDFrame]:
        """Generate a complete chronological sequence of CAN-FD frames.

        Args:
            duration_ms: Length of the simulation trace in milliseconds.
            start_time_us: Initial simulation timestamp in microseconds.
            suppression_hooks: Optional callable(time_us) returning set of currently suppressed IDs.

        Returns:
            List of CANFDFrame objects sorted chronologically by timestamp_us.
        """
        end_time_us = start_time_us + (duration_ms * 1000)
        event_queue: list[ScheduledMessage] = []

        # Stagger initial message transmissions to prevent artificial simultaneous bursts
        for msg_id, msg_def in sorted(self.message_defs.items()):
            interval_us = msg_def.period_ms * 1000
            # Phase offset deterministic based on message ID
            initial_offset_us = (msg_id * 137) % min(interval_us, 5000)
            heapq.heappush(
                event_queue,
                ScheduledMessage(scheduled_time_us=start_time_us + initial_offset_us, message_id=msg_id),
            )

        frames: list[CANFDFrame] = []

        while event_queue:
            evt = heapq.heappop(event_queue)
            t_us = evt.scheduled_time_us
            if t_us >= end_time_us:
                break

            msg_id = evt.message_id
            msg_def = self.message_defs[msg_id]

            # Determine if this message is currently suppressed
            currently_suppressed = self.suppressed_ids
            if suppression_hooks is not None:
                currently_suppressed = currently_suppressed.union(suppression_hooks(t_us))

            if msg_id not in currently_suppressed:
                # Sample physical signals at current timestamp
                signals = self.signal_gen.generate_signals(t_us)
                msg_signals = signals.get(msg_id, {})
                payload_bytes = bytes(msg_def.pack(msg_signals))

                frame = CANFDFrame(
                    timestamp_us=t_us,
                    arbitration_id=msg_id,
                    dlc=msg_def.dlc,
                    data=payload_bytes,
                    is_extended=False,
                    brs=True,
                    esi=False,
                    label=0,
                    attack_name="Normal",
                )
                frames.append(frame)

            # Schedule subsequent transmission with realistic ECU timer jitter (+-50 us)
            interval_us = msg_def.period_ms * 1000
            jitter_us = self.rng.randint(-50, 50)
            next_time_us = t_us + interval_us + jitter_us
            heapq.heappush(
                event_queue,
                ScheduledMessage(scheduled_time_us=next_time_us, message_id=msg_id),
            )

        return frames
