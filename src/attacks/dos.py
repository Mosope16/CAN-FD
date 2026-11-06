"""Denial of Service (DoS) Bus Flooding Attack.

Injects high-priority dominant identifier frames at microsecond intervals,
saturating the CAN-FD bus arbitration and starving legitimate ECUs.
"""

from __future__ import annotations

from typing import List
from src.generator.traffic_generator import CANFDFrame


class DoSAttack:
    """Generates a burst of high-priority CAN-FD frames."""

    def __init__(
        self,
        start_ms: int,
        duration_ms: int,
        target_id: int = 0x050,
        interval_us: int = 500,
        dlc: int = 8,
        payload_pattern: bytes = b"\xDE\xAD\xBE\xEF\x00\x00\x00\x00",
    ) -> None:
        self.start_us = start_ms * 1000
        self.end_us = (start_ms + duration_ms) * 1000
        self.target_id = target_id
        self.interval_us = interval_us
        self.dlc = dlc
        self.payload = payload_pattern

    def generate_frames(self) -> list[CANFDFrame]:
        """Generate the series of flooding frames within the attack time window."""
        frames: list[CANFDFrame] = []
        curr_us = self.start_us
        while curr_us < self.end_us:
            frame = CANFDFrame(
                timestamp_us=curr_us,
                arbitration_id=self.target_id,
                dlc=self.dlc,
                data=self.payload,
                is_extended=False,
                brs=True,
                esi=False,
                label=1,
                attack_name="DoS",
            )
            frames.append(frame)
            curr_us += self.interval_us
        return frames
