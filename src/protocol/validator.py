"""CAN-FD Protocol Validator and Physical Corruption Detector.

Enforces protocol sanity rules, identifies bit-level corruption patterns,
and separates protocol defects from behavioral attack anomalies.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from src.generator.message_definitions import DLC_TO_BYTES_MAP
from src.protocol.frame_decoder import FrameDecoder, ProtocolValidationReport


class ProtocolValidator:
    """Validates low-level bitstream structures and frame conformity."""

    def __init__(self) -> None:
        self.total_checked = 0
        self.total_errors = 0
        self.error_history: list[ProtocolValidationReport] = []

    def validate_stream(
        self,
        raw_bits: list[int],
        timestamp_us: int = 0,
    ) -> ProtocolValidationReport:
        """Inspect a raw bit stream and return full protocol diagnostic report."""
        self.total_checked += 1
        _, report = FrameDecoder.decode_stream(raw_bits, timestamp_us=timestamp_us)
        if not report.is_valid:
            self.total_errors += 1
            self.error_history.append(report)
        return report

    @staticmethod
    def is_dlc_valid(dlc: int) -> bool:
        """Verify that DLC is within ISO 11898-1:2015 4-bit range."""
        return 0 <= dlc <= 15
