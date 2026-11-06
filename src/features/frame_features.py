"""CAN-FD Integer Feature Representation.

Defines the 14-element fixed-point and integer feature structure used by
both the Python Decision Tree classifier and exported ANSI C engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict


FEATURE_NAMES: list[str] = [
    "frame_id",
    "frame_dlc",
    "payload_delta",
    "inter_arrival",
    "period_deviation",
    "id_rate",
    "total_bus_rate",
    "id_seen_before",
    "dlc_mismatch",
    "payload_change_count",
    "protocol_error_count",
    "missing_frame_count",
    "replay_similarity",
    "duplicate_count",
]


@dataclass
class CANFDFeatures:
    """Integer feature vector for a CAN-FD transmission or missing-frame event."""

    frame_id: int
    frame_dlc: int
    payload_delta: int
    inter_arrival: int
    period_deviation: int
    id_rate: int
    total_bus_rate: int
    id_seen_before: int
    dlc_mismatch: int
    payload_change_count: int
    protocol_error_count: int
    missing_frame_count: int
    replay_similarity: int
    duplicate_count: int

    def to_list(self) -> list[int]:
        """Convert features to integer list in standardized schema order."""
        return [
            int(self.frame_id),
            int(self.frame_dlc),
            int(self.payload_delta),
            int(self.inter_arrival),
            int(self.period_deviation),
            int(self.id_rate),
            int(self.total_bus_rate),
            int(self.id_seen_before),
            int(self.dlc_mismatch),
            int(self.payload_change_count),
            int(self.protocol_error_count),
            int(self.missing_frame_count),
            int(self.replay_similarity),
            int(self.duplicate_count),
        ]

    def to_dict(self) -> dict[str, int]:
        """Return named dictionary of integer features."""
        return dict(zip(FEATURE_NAMES, self.to_list()))
