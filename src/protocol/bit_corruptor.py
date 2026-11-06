"""CAN-FD Physical Bit Corruptor for Protocol Robustness Validation.

Deliberately injects bit-level inversions, stuffing violations, and delimiter
errors to evaluate protocol-layer detection conformance (REQ-06).
"""

from __future__ import annotations

import copy
from typing import List
from src.protocol.frame_builder import PhysicalBitStream


class BitCorruptor:
    """Injects precise physical layer bit disturbances into a PhysicalBitStream."""

    @staticmethod
    def corrupt_crc_bit(stream: PhysicalBitStream, bit_offset_in_crc: int = 2) -> PhysicalBitStream:
        """Invert a bit inside the CRC remainder field."""
        new_stream = copy.deepcopy(stream)
        # CRC field starts at index len(stream.stuffed_header_and_data)
        crc_start_idx = len(new_stream.stuffed_header_and_data)
        # Target bit in CRC (after fixed stuff bit 0, stuff count 4 bits, fixed stuff 1)
        target_idx = crc_start_idx + 6 + bit_offset_in_crc
        if target_idx < len(new_stream.bits):
            new_stream.bits[target_idx] = 1 - new_stream.bits[target_idx]
        return new_stream

    @staticmethod
    def inject_dynamic_stuff_violation(stream: PhysicalBitStream) -> PhysicalBitStream:
        """Inject 6 consecutive identical bits into the stuffed data stream."""
        new_stream = copy.deepcopy(stream)
        # Find 5 consecutive identical bits in stuffed header/data or force 6 identical bits
        if len(new_stream.bits) >= 20:
            for i in range(10, 16):
                new_stream.bits[i] = 1  # Force 6 consecutive 1s
        return new_stream

    @staticmethod
    def corrupt_fixed_stuff_bit(stream: PhysicalBitStream, fixed_stuff_index: int = 0) -> PhysicalBitStream:
        """Invert a fixed stuff bit inside the CRC field."""
        new_stream = copy.deepcopy(stream)
        crc_start_idx = len(new_stream.stuffed_header_and_data)
        # fixed_stuff_index 0 is FS0 (at crc_start_idx)
        # fixed_stuff_index 1 is FS1 (at crc_start_idx + 5)
        if fixed_stuff_index == 0:
            target_idx = crc_start_idx
        else:
            target_idx = crc_start_idx + 5

        if target_idx < len(new_stream.bits):
            new_stream.bits[target_idx] = 1 - new_stream.bits[target_idx]
        return new_stream

    @staticmethod
    def corrupt_ack_delimiter(stream: PhysicalBitStream) -> PhysicalBitStream:
        """Force the recessive ACK delimiter (1) to dominant (0)."""
        new_stream = copy.deepcopy(stream)
        # ACK delimiter is the 2nd bit of ack_and_eof
        eof_start_idx = len(new_stream.stuffed_header_and_data) + len(new_stream.crc_field_bits)
        ack_delimiter_idx = eof_start_idx + 1
        if ack_delimiter_idx < len(new_stream.bits):
            new_stream.bits[ack_delimiter_idx] = 0  # Force dominant
        return new_stream
