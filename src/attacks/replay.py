"""Replay Attack Engine.

Captures legitimate CAN-FD frame sequences during benign operational intervals
and retransmits them verbatim at later simulation intervals, undermining freshness.
"""

from __future__ import annotations

from typing import List
from src.generator.traffic_generator import CANFDFrame


class ReplayAttack:
    """Replays previously recorded legitimate frames."""

    def __init__(
        self,
        replay_start_ms: int,
        target_id: int,
        recorded_frames: list[CANFDFrame],
    ) -> None:
        self.replay_start_us = replay_start_ms * 1000
        self.target_id = target_id
        # Filter recorded frames to target ID
        self.recorded_frames = [f for f in recorded_frames if f.arbitration_id == target_id]

    @classmethod
    def capture_and_schedule(
        cls,
        frames_pool: list[CANFDFrame],
        target_id: int,
        capture_start_ms: int,
        capture_duration_ms: int,
        replay_start_ms: int,
    ) -> ReplayAttack:
        """Extract historical frames from a baseline frame pool and schedule for replay."""
        c_start_us = capture_start_ms * 1000
        c_end_us = (capture_start_ms + capture_duration_ms) * 1000
        recorded = [
            f for f in frames_pool
            if f.arbitration_id == target_id and c_start_us <= f.timestamp_us < c_end_us
        ]
        return cls(replay_start_ms=replay_start_ms, target_id=target_id, recorded_frames=recorded)

    def generate_frames(self) -> list[CANFDFrame]:
        """Generate replayed frames shifted to the attack timestamp window."""
        if not self.recorded_frames:
            return []

        first_orig_us = self.recorded_frames[0].timestamp_us
        replayed: list[CANFDFrame] = []

        for f in self.recorded_frames:
            relative_offset = f.timestamp_us - first_orig_us
            replayed_frame = CANFDFrame(
                timestamp_us=self.replay_start_us + relative_offset,
                arbitration_id=f.arbitration_id,
                dlc=f.dlc,
                data=f.data,
                is_extended=f.is_extended,
                brs=f.brs,
                esi=f.esi,
                label=4,
                attack_name="Replay",
            )
            replayed.append(replayed_frame)
        return replayed
