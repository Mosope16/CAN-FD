"""CAN-FD Message and Signal Definitions (DBC-style).

Implements ISO 11898-1:2015 DLC-to-byte length mappings, signal packing,
and network configuration loaders.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import yaml


# ISO 11898-1:2015 Table 4 - DLC to Data Field Length Mapping
DLC_TO_BYTES_MAP: dict[int, int] = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 7,
    8: 8,
    9: 12,
    10: 16,
    11: 20,
    12: 24,
    13: 32,
    14: 48,
    15: 64,
}

# Reverse mapping: byte count to minimal matching DLC
BYTES_TO_DLC_MAP: dict[int, int] = {}
for _dlc, _bytes in sorted(DLC_TO_BYTES_MAP.items()):
    if _bytes not in BYTES_TO_DLC_MAP:
        BYTES_TO_DLC_MAP[_bytes] = _dlc


def dlc_to_bytes(dlc: int) -> int:
    """Return number of data bytes corresponding to a CAN-FD DLC (0-15)."""
    if dlc < 0 or dlc > 15:
        raise ValueError(f"Invalid CAN-FD DLC: {dlc}. Must be 0..15.")
    return DLC_TO_BYTES_MAP[dlc]


def bytes_to_dlc(byte_len: int) -> int:
    """Return the minimum CAN-FD DLC required to carry byte_len bytes (0..64)."""
    if byte_len < 0 or byte_len > 64:
        raise ValueError(f"Payload length {byte_len} exceeds CAN-FD limit of 64 bytes.")
    for dlc in range(16):
        if DLC_TO_BYTES_MAP[dlc] >= byte_len:
            return dlc
    return 15


@dataclass
class SignalDefinition:
    """Defines a physical signal embedded within a CAN-FD message."""

    name: str
    start_byte: int
    num_bytes: int
    min_val: float
    max_val: float
    scale: float = 1.0
    offset: float = 0.0
    unit: str = ""

    def encode(self, physical_val: float) -> bytes:
        """Encode physical float value into big-endian integer payload bytes."""
        clamped = max(self.min_val, min(self.max_val, physical_val))
        raw_int = int(round((clamped - self.offset) / self.scale))
        if self.num_bytes == 1:
            return struct.pack(">B", raw_int & 0xFF)
        elif self.num_bytes == 2:
            return struct.pack(">H", raw_int & 0xFFFF)
        elif self.num_bytes == 4:
            return struct.pack(">I", raw_int & 0xFFFFFFFF)
        else:
            return raw_int.to_bytes(self.num_bytes, byteorder="big", signed=False)

    def decode(self, payload: bytes) -> float:
        """Decode big-endian raw bytes into physical float value."""
        raw_slice = payload[self.start_byte : self.start_byte + self.num_bytes]
        if len(raw_slice) < self.num_bytes:
            raise ValueError(f"Payload too short ({len(payload)}) for signal {self.name} of length {self.num_bytes}")
        if self.num_bytes == 1:
            raw_int = struct.unpack(">B", raw_slice)[0]
        elif self.num_bytes == 2:
            raw_int = struct.unpack(">H", raw_slice)[0]
        elif self.num_bytes == 4:
            raw_int = struct.unpack(">I", raw_slice)[0]
        else:
            raw_int = int.from_bytes(raw_slice, byteorder="big", signed=False)
        return float(raw_int * self.scale + self.offset)


@dataclass
class MessageDefinition:
    """Defines a CAN-FD frame schema with period, DLC, and signal layout."""

    id: int
    name: str
    period_ms: int
    dlc: int
    description: str = ""
    signals: list[SignalDefinition] = field(default_factory=list)

    @property
    def payload_bytes(self) -> int:
        return dlc_to_bytes(self.dlc)

    def pack(self, signal_values: dict[str, float]) -> bytearray:
        """Pack physical signal values into a fixed-length CAN-FD payload."""
        total_len = self.payload_bytes
        buf = bytearray(total_len)
        for sig in self.signals:
            if sig.name in signal_values:
                encoded = sig.encode(signal_values[sig.name])
                buf[sig.start_byte : sig.start_byte + sig.num_bytes] = encoded
        return buf

    def unpack(self, payload: bytes) -> dict[str, float]:
        """Extract physical signal values from raw payload bytes."""
        values = {}
        for sig in self.signals:
            if len(payload) >= sig.start_byte + sig.num_bytes:
                values[sig.name] = sig.decode(payload)
        return values


def load_network_config(yaml_path: str) -> dict[int, MessageDefinition]:
    """Parse YAML network configuration into a mapping of CAN ID to MessageDefinition."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    msg_map: dict[int, MessageDefinition] = {}
    for entry in data.get("messages", []):
        signals = [
            SignalDefinition(
                name=s["name"],
                start_byte=s["start_byte"],
                num_bytes=s["num_bytes"],
                min_val=float(s.get("min_val", 0.0)),
                max_val=float(s.get("max_val", 255.0)),
                scale=float(s.get("scale", 1.0)),
                offset=float(s.get("offset", 0.0)),
                unit=s.get("unit", ""),
            )
            for s in entry.get("signals", [])
        ]
        msg_def = MessageDefinition(
            id=entry["id"] if isinstance(entry["id"], int) else int(entry["id"], 16),
            name=entry["name"],
            period_ms=int(entry["period_ms"]),
            dlc=int(entry["dlc"]),
            description=entry.get("description", ""),
            signals=signals,
        )
        msg_map[msg_def.id] = msg_def
    return msg_map
