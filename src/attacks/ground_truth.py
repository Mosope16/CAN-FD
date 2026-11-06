"""Ground-Truth Manager and Simulation Attack Orchestrator.

Maintains ground-truth attack metadata and event logs while enforcing strict
decoupling from the IDS feature extraction and classification pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import yaml

from src.generator.traffic_generator import CANFDFrame


@dataclass
class AttackEvent:
    """Ground-truth metadata record for an attack window."""

    attack_type: int
    name: str
    target_id: Optional[int]
    start_us: int
    end_us: int
    description: str = ""

    def contains(self, timestamp_us: int, arbitration_id: Optional[int] = None) -> bool:
        """Check if an event matches the temporal and ID bounds."""
        time_match = self.start_us <= timestamp_us <= self.end_us
        if not time_match:
            return False
        if self.target_id is not None and arbitration_id is not None:
            return self.target_id == arbitration_id
        return True


class GroundTruthManager:
    """Orchestrates attack definitions and maintains isolated ground-truth logs."""

    def __init__(self) -> None:
        self.events: list[AttackEvent] = []

    def register_event(
        self,
        attack_type: int,
        name: str,
        start_ms: int,
        duration_ms: int,
        target_id: Optional[int] = None,
        description: str = "",
    ) -> AttackEvent:
        """Register an active attack episode."""
        evt = AttackEvent(
            attack_type=attack_type,
            name=name,
            target_id=target_id,
            start_us=start_ms * 1000,
            end_us=(start_ms + duration_ms) * 1000,
            description=description,
        )
        self.events.append(evt)
        return evt

    def get_ground_truth_label(self, frame: CANFDFrame) -> int:
        """Determine true label for a frame based on registered events."""
        # Frame's embedded label from generator is the authoritative ground truth
        return frame.label

    def get_active_attacks(self, timestamp_us: int) -> list[AttackEvent]:
        """Query attacks active at a specific timestamp."""
        return [e for e in self.events if e.start_us <= timestamp_us <= e.end_us]
