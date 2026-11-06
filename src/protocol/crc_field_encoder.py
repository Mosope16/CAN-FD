"""ISO 11898-1:2015 CAN-FD CRC Field Encoder & Safeguards.

Implements fixed stuff bit insertion every 4 bits within the CRC field,
Stuff Count field integration, and receiver CRC field fixed-stuff validation.
"""

from __future__ import annotations

from typing import List, Tuple
from src.protocol.crc_engine import (
    CRC17_LEN,
    CRC17_POLY,
    CRC21_LEN,
    CRC21_POLY,
    compute_crc,
    compute_stuff_count_bits,
    decode_stuff_count_bits,
    int_to_bit_list,
    bit_list_to_int,
)


def encode_crc_field(
    last_bit_before_crc: int,
    dynamic_stuff_count: int,
    crc_remainder: int,
    crc_len: int,
) -> list[int]:
    """Construct the complete physical CRC field including fixed stuff bits.

    Format:
    [FixedStuff0] + [StuffCount 4 bits] + [FixedStuff1] + [CRC bits with fixed stuff every 4 bits] + [CRC Delimiter]

    Args:
        last_bit_before_crc: 0 or 1, the value of the bit directly preceding the CRC field.
        dynamic_stuff_count: Number of dynamic stuff bits in SOF-Data fields.
        crc_remainder: Integer CRC remainder.
        crc_len: 17 or 21.

    Returns:
        List of physical bits comprising the entire CRC field.
    """
    crc_field_bits: list[int] = []

    # 1. Fixed Stuff Bit 0 (complement of last bit before CRC)
    fs0 = 1 - last_bit_before_crc
    crc_field_bits.append(fs0)

    # 2. Stuff Count field: 3 bits Gray code + 1 parity bit = 4 bits
    stuff_count_4bits = compute_stuff_count_bits(dynamic_stuff_count)
    crc_field_bits.extend(stuff_count_4bits)

    # 3. Fixed Stuff Bit 1 (complement of last bit of Stuff Count)
    fs1 = 1 - crc_field_bits[-1]
    crc_field_bits.append(fs1)

    # 4. CRC sequence with fixed stuff bits inserted every 4 bits
    raw_crc_bits = int_to_bit_list(crc_remainder, crc_len)
    for idx, bit in enumerate(raw_crc_bits):
        crc_field_bits.append(bit)
        # After every 4 CRC bits, if not at the very end of the CRC sequence
        if (idx + 1) % 4 == 0 and (idx + 1) < crc_len:
            # Fixed stuff bit of opposite polarity to the preceding bit
            fs = 1 - bit
            crc_field_bits.append(fs)

    # 5. CRC Delimiter: 1 recessive bit (1)
    crc_field_bits.append(1)

    return crc_field_bits


def decode_and_validate_crc_field(
    crc_field_bits: list[int],
    crc_len: int,
    last_bit_before_crc: int,
) -> tuple[int, int, bool, bool, bool]:
    """Parse and validate physical CRC field bits.

    Args:
        crc_field_bits: Bits of the received CRC field.
        crc_len: Expected CRC length (17 or 21).
        last_bit_before_crc: Preceding bit value.

    Returns:
        (stuff_count, received_crc, fixed_stuff_ok, parity_ok, delimiter_ok)
    """
    fixed_stuff_ok = True
    ptr = 0

    # 1. Check Fixed Stuff Bit 0
    if ptr >= len(crc_field_bits):
        return -1, 0, False, False, False
    fs0 = crc_field_bits[ptr]
    if fs0 != (1 - last_bit_before_crc):
        fixed_stuff_ok = False
    ptr += 1

    # 2. Stuff Count 4 bits
    if ptr + 4 > len(crc_field_bits):
        return -1, 0, False, False, False
    sc_bits = crc_field_bits[ptr : ptr + 4]
    stuff_count, parity_ok = decode_stuff_count_bits(sc_bits)
    ptr += 4

    # 3. Check Fixed Stuff Bit 1
    if ptr >= len(crc_field_bits):
        return stuff_count, 0, False, parity_ok, False
    fs1 = crc_field_bits[ptr]
    if fs1 != (1 - crc_field_bits[ptr - 1]):
        fixed_stuff_ok = False
    ptr += 1

    # 4. Extract CRC bits, validating fixed stuff bits every 4 bits
    extracted_crc_bits: list[int] = []
    while len(extracted_crc_bits) < crc_len and ptr < len(crc_field_bits):
        bit = crc_field_bits[ptr]
        extracted_crc_bits.append(bit)
        ptr += 1

        if len(extracted_crc_bits) % 4 == 0 and len(extracted_crc_bits) < crc_len:
            if ptr >= len(crc_field_bits):
                fixed_stuff_ok = False
                break
            fs = crc_field_bits[ptr]
            if fs != (1 - bit):
                fixed_stuff_ok = False
            ptr += 1

    received_crc = bit_list_to_int(extracted_crc_bits) if len(extracted_crc_bits) == crc_len else 0

    # 5. CRC Delimiter
    delimiter_ok = False
    if ptr < len(crc_field_bits):
        delimiter_ok = (crc_field_bits[ptr] == 1)

    return stuff_count, received_crc, fixed_stuff_ok, parity_ok, delimiter_ok
