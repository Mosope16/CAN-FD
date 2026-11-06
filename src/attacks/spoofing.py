"""Spoofing / Masquerade Attack Engine.

Injects counterfeit frames using valid network CAN identifiers but with
falsified sensor data and anomalous transmission frequencies.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from src.generator.message_definitions import MessageDefinition
from src.generator.traffic_generator import CANFDFrame


class SpoofingAttack:
    """Injects counterfeit frames impersonating an existing ECU."""

    def __init__(
        self,
        start_ms: int,
        duration_ms: int,
        target_id: int,
        interval_us: int,
        spoofed_payload: bytes,
        dlc: int = 8,
    ) -> None:
        self.start_us = start_ms * 1000
        self.end_us = (start_ms + duration_ms) * 1000
        self.target_id = target_id
        self.interval_us = interval_us
        self.spoofed_payload = spoofed_payload
        self.dlc = dlc

    @classmethod
    def from_signals(
        cls,
        start_ms: int,
        duration_ms: int,
        msg_def: MessageDefinition,
        interval_us: int,
        spoofed_signals: dict[str, float],
    ) -> SpoofingAttack:
        """Construct spoofing attack from DBC message definition and target signals."""
        packed_payload = bytes(msg_def.pack(spoofed_signals))
        return cls(
            start_ms=start_ms,
            duration_ms=duration_ms,
            target_id=msg_def.id,
            interval_us=interval_us,
            spoofed_payload=packed_payload,
            dlc=msg_def.dlc,
        )

    def generate_frames(self) -> list[CANFDFrame]:
        """Generate sequence of spoofed frames."""
        frames: list[CANFDFrame] = []
        curr_us = self.start_us
        while curr_us < self.end_us:
            frame = CANFDFrame(
                timestamp_us=curr_us,
                arbitration_id=self.target_id,
                dlc=self.dlc,
                data=self.spoofed_payload,
                is_extended=False,
                brs=True,
                esi=False,
                label=3,
                attack_name="Spoofing",
            )
            frames.append(frame)
            curr_us += self.interval_us
        return frames
