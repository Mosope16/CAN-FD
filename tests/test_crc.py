"""Unit tests for CAN-FD CRC Engine and Stuff Counter."""

import pytest
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


def test_bit_conversion():
    val = 0x1685B
    bits = int_to_bit_list(val, 17)
    assert len(bits) == 17
    assert bit_list_to_int(bits) == val


def test_stuff_count_gray_and_parity():
    for count in range(16):
        sc_bits = compute_stuff_count_bits(count)
        assert len(sc_bits) == 4
        # Even parity check: sum of bits must be even
        assert sum(sc_bits) % 2 == 0
        decoded_val, is_valid = decode_stuff_count_bits(sc_bits)
        assert is_valid is True
        assert decoded_val == (count % 8)


def test_crc17_deterministic():
    # Test with sample bitstream
    test_bits = [0, 1, 0, 1, 1, 0, 0, 1] * 8
    crc1 = compute_crc(test_bits, CRC17_POLY, CRC17_LEN)
    crc2 = compute_crc(test_bits, CRC17_POLY, CRC17_LEN)
    assert crc1 == crc2
    assert 0 <= crc1 < (1 << 17)


def test_crc21_deterministic():
    test_bits = [1, 0, 1, 1, 0, 0, 1, 0] * 16
    crc1 = compute_crc(test_bits, CRC21_POLY, CRC21_LEN)
    crc2 = compute_crc(test_bits, CRC21_POLY, CRC21_LEN)
    assert crc1 == crc2
    assert 0 <= crc1 < (1 << 21)
