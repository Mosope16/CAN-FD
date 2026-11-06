"""Bus Fuzzing Attack Engine.

Injects randomized CAN identifiers, unpredictable DLC sizes, and unstructured
random payload payloads to probe for receiver parsing flaws and buffer overflows.
"""

from __future__ import annotations

import random
from typing import List, Tuple
from src.generator.message_definitions import dlc_to_bytes
from src.generator.traffic_generator import CANFDFrame


class FuzzingAttack:
    """Injects randomized CAN-FD frames into the bus stream."""

    def __init__(
        self,
        start_ms: int,
        duration_ms: int,
        interval_us: int = 2000,
        id_range: tuple[int, int] = (0x000, 0x7FF),
        dlc_range: tuple[int, int] = (0, 15),
        seed: int = 12345,
    ) -> None:
        self.start_us = start_ms * 1000
        self.end_us = (start_ms + duration_ms) * 1000
        self.interval_us = interval_us
        self.id_range = id_range
        self.dlc_range = dlc_range
        self.rng = random.Random(seed)

    def generate_frames(self) -> list[CANFDFrame]:
        """Generate fuzzed frames over the attack window."""
        frames: list[CANFDFrame] = []
        curr_us = self.start_us
        while curr_us < self.end_us:
            rand_id = self.rng.randint(self.id_range[0], self.id_range[1])
            rand_dlc = self.rng.randint(self.dlc_range[0], self.dlc_range[1])
            payload_len = dlc_to_bytes(rand_dlc)
            rand_data = bytes(self.rng.randint(0, 255) for _ in range(payload_len))

            frame = CANFDFrame(
                timestamp_us=curr_us,
                arbitration_id=rand_id,
                dlc=rand_dlc,
                data=rand_data,
                is_extended=False,
                brs=True,
                esi=False,
                label=2,
                attack_name="Fuzzing",
            )
            frames.append(frame)
            curr_us += self.interval_us
        return frames
