"""ISO CAN-FD Logical Frame Serializer and Bit-Stream Builder.

Constructs complete physical bit streams from logical CANFDFrame objects,
including dynamic bit stuffing, CRC calculation, and ISO fixed-stuff safeguards.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from src.generator.message_definitions import dlc_to_bytes
from src.generator.traffic_generator import CANFDFrame
from src.protocol.bit_stuffer import apply_dynamic_bit_stuffing
from src.protocol.crc_engine import (
    CRC17_LEN,
    CRC17_POLY,
    CRC21_LEN,
    CRC21_POLY,
    compute_crc,
    int_to_bit_list,
)
from src.protocol.crc_field_encoder import encode_crc_field


@dataclass
class PhysicalBitStream:
    """Represents the fully serialized physical bit stream of a CAN-FD frame."""

    bits: list[int]
    unstuffed_header_and_data: list[int]
    stuffed_header_and_data: list[int]
    crc_field_bits: list[int]
    ack_and_eof_bits: list[int]
    dynamic_stuff_count: int
    crc_remainder: int
    crc_len: int
    nominal_bit_count: int
    data_bit_count: int


class FrameBuilder:
    """Serializes logical CANFDFrame instances into physical ISO CAN-FD bit streams."""

    @staticmethod
    def serialize_frame(frame: CANFDFrame) -> PhysicalBitStream:
        """Convert a CANFDFrame to its complete physical bit representation.

        Args:
            frame: Logical CANFDFrame instance.

        Returns:
            PhysicalBitStream containing complete bit stream and structural diagnostics.
        """
        # A physical CAN-FD DLC is a four-bit field; reject invalid logical
        # values before attempting to encode the frame.
        expected_bytes = dlc_to_bytes(frame.dlc)
        raw_bits: list[int] = []

        # 1. SOF: Start of Frame (1 dominant bit = 0)
        raw_bits.append(0)

        # 2. Arbitration & Control Fields
        if not frame.is_extended:
            # 11-bit Standard Identifier
            raw_bits.extend(int_to_bit_list(frame.arbitration_id, 11))
            raw_bits.append(0)  # RRS (Remote Request Substitution, dominant 0 in FD)
            raw_bits.append(0)  # IDE (Identifier Extension, dominant 0 for standard)
            raw_bits.append(1)  # FDF (FD Format Indicator, recessive 1 for CAN-FD)
        else:
            # 29-bit Extended Identifier
            base_id = (frame.arbitration_id >> 18) & 0x7FF
            ext_id = frame.arbitration_id & 0x3FFFF
            raw_bits.extend(int_to_bit_list(base_id, 11))
            raw_bits.append(1)  # SRR (Substitute Remote Request, recessive 1)
            raw_bits.append(1)  # IDE (Identifier Extension, recessive 1 for extended)
            raw_bits.extend(int_to_bit_list(ext_id, 18))
            raw_bits.append(0)  # RRS (dominant 0 in FD)
            raw_bits.append(1)  # FDF (recessive 1 for CAN-FD)

        # Control Field
        raw_bits.append(0)                       # res (reserved bit, dominant 0)
        raw_bits.append(1 if frame.brs else 0)   # BRS (Bit Rate Switch)
        raw_bits.append(1 if frame.esi else 0)   # ESI (Error State Indicator)
        raw_bits.extend(int_to_bit_list(frame.dlc, 4))  # DLC (4 bits)

        # 3. Data Field
        padded_payload = frame.data.ljust(expected_bytes, b"\x00")
        for byte_val in padded_payload:
            raw_bits.extend(int_to_bit_list(byte_val, 8))

        unstuffed_header_and_data = list(raw_bits)

        # 4. CRC Selection & Computation
        # In ISO CAN-FD: DLC <= 10 (0..16 bytes) -> CRC-17; DLC > 10 (20..64 bytes) -> CRC-21
        crc_len = CRC17_LEN if frame.dlc <= 10 else CRC21_LEN
        crc_poly = CRC17_POLY if frame.dlc <= 10 else CRC21_POLY
        crc_remainder = compute_crc(unstuffed_header_and_data, crc_poly, crc_len)

        # 5. Dynamic Bit Stuffing on Header + Data
        stuffed_bits, dynamic_stuff_count = apply_dynamic_bit_stuffing(unstuffed_header_and_data)
        last_bit_before_crc = stuffed_bits[-1] if stuffed_bits else 0

        # 6. CRC Field Encoding (Fixed stuff bits, Stuff count, Remainder, Delimiter)
        crc_field = encode_crc_field(
            last_bit_before_crc=last_bit_before_crc,
            dynamic_stuff_count=dynamic_stuff_count,
            crc_remainder=crc_remainder,
            crc_len=crc_len,
        )

        # 7. ACK and EOF Fields
        ack_and_eof = [
            1,  # ACK slot (transmitted as recessive 1)
            1,  # ACK delimiter (recessive 1)
            1, 1, 1, 1, 1, 1, 1,  # EOF (7 recessive 1s)
            1, 1, 1,              # IFS / Intermission (3 recessive 1s)
        ]

        full_stream = stuffed_bits + crc_field + ack_and_eof

        # Calculate bit counts for nominal vs data phase
        # Data phase begins at BRS sample point and ends at CRC delimiter sample point
        # Approximate: nominal = arbitration + control_prefix (15 bits) + ack_and_eof (12 bits)
        nominal_count = 15 + len(ack_and_eof)
        data_count = len(full_stream) - nominal_count

        return PhysicalBitStream(
            bits=full_stream,
            unstuffed_header_and_data=unstuffed_header_and_data,
            stuffed_header_and_data=stuffed_bits,
            crc_field_bits=crc_field,
            ack_and_eof_bits=ack_and_eof,
            dynamic_stuff_count=dynamic_stuff_count,
            crc_remainder=crc_remainder,
            crc_len=crc_len,
            nominal_bit_count=nominal_count,
            data_bit_count=data_count,
        )
