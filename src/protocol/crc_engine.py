"""ISO 11898-1:2015 CAN-FD CRC Engine and Stuff Counter.

Implements CRC-17 (DLC <= 10) and CRC-21 (DLC > 10) generator polynomials,
Stuff Count Gray coding, and even parity bit computation.
"""

from __future__ import annotations

from typing import List, Tuple


# ISO 11898-1:2015 CRC Polynomials
# CRC-17: x^17 + x^16 + x^14 + x^13 + x^11 + x^6 + x^4 + x^3 + x^1 + 1 -> 0x1685B
CRC17_POLY = 0x1685B
CRC17_LEN = 17

# CRC-21: x^21 + x^20 + x^13 + x^11 + x^7 + x^4 + x^3 + 1 -> 0x102899
CRC21_POLY = 0x102899
CRC21_LEN = 21

# Gray-code lookup table for Stuff Count modulo 8 (ISO 11898-1:2015 Table 6)
# Value -> 3-bit Gray code
GRAY_CODE_MAP = {
    0: [0, 0, 0],
    1: [0, 0, 1],
    2: [0, 1, 1],
    3: [0, 1, 0],
    4: [1, 1, 0],
    5: [1, 1, 1],
    6: [1, 0, 1],
    7: [1, 0, 0],
}

# Reverse Gray code map: tuple of 3 bits -> int value 0..7
REVERSE_GRAY_MAP = {tuple(v): k for k, v in GRAY_CODE_MAP.items()}


def compute_stuff_count_bits(dynamic_stuff_count: int) -> list[int]:
    """Compute the 4-bit Stuff Count field (3 Gray code bits + 1 even parity bit).

    Args:
        dynamic_stuff_count: Number of dynamic stuff bits inserted prior to CRC field.

    Returns:
        List of 4 integer bits [g2, g1, g0, parity].
    """
    val = dynamic_stuff_count % 8
    gray_bits = list(GRAY_CODE_MAP[val])
    # Parity: bit such that total number of 1s is even
    ones_count = sum(gray_bits)
    parity_bit = 1 if (ones_count % 2 != 0) else 0
    return gray_bits + [parity_bit]


def decode_stuff_count_bits(bits4: list[int]) -> tuple[int, bool]:
    """Decode 4-bit Stuff Count field into integer value and parity valid flag.

    Returns:
        (stuff_count_mod8, is_parity_valid)
    """
    if len(bits4) != 4:
        raise ValueError(f"Stuff count field must be exactly 4 bits, got {len(bits4)}")
    gray_tuple = tuple(bits4[:3])
    parity_bit = bits4[3]
    total_ones = sum(bits4)
    is_valid = (total_ones % 2 == 0) and (gray_tuple in REVERSE_GRAY_MAP)
    decoded_val = REVERSE_GRAY_MAP.get(gray_tuple, -1)
    return decoded_val, is_valid


def compute_crc(bits: list[int], poly: int, crc_len: int) -> int:
    """Compute polynomial CRC remainder over bit sequence.

    Args:
        bits: Stream of bits [0 or 1] from SOF through end of Data Field.
        poly: Generator polynomial without the x^N leading bit.
        crc_len: Polynomial degree (17 or 21).

    Returns:
        Integer checksum remainder.
    """
    crc = 0
    mask = (1 << crc_len) - 1
    # Feed input bits followed by crc_len zeros (polynomial multiplication by x^N)
    for bit in bits:
        msb = (crc >> (crc_len - 1)) & 1
        crc = ((crc << 1) | bit) & mask
        if msb:
            crc ^= poly

    for _ in range(crc_len):
        msb = (crc >> (crc_len - 1)) & 1
        crc = (crc << 1) & mask
        if msb:
            crc ^= poly

    return crc


def int_to_bit_list(val: int, length: int) -> list[int]:
    """Convert integer to MSB-first bit list of fixed length."""
    return [(val >> (length - 1 - i)) & 1 for i in range(length)]


def bit_list_to_int(bits: list[int]) -> int:
    """Convert MSB-first bit list to integer value."""
    res = 0
    for b in bits:
        res = (res << 1) | (b & 1)
    return res
