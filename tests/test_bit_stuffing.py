"""Unit tests for Dynamic Bit Stuffing and Destuffing."""

import pytest
from src.protocol.bit_stuffer import apply_dynamic_bit_stuffing, remove_dynamic_bit_stuffing


def test_bit_stuffing_five_ones():
    # 5 consecutive 1s should have a 0 stuff bit inserted
    raw = [1, 1, 1, 1, 1]
    stuffed, count = apply_dynamic_bit_stuffing(raw)
    assert count == 1
    assert stuffed == [1, 1, 1, 1, 1, 0]

    destuffed, rem_count, err = remove_dynamic_bit_stuffing(stuffed)
    assert err is False
    assert rem_count == 1
    assert destuffed == raw


def test_bit_stuffing_five_zeros():
    # 5 consecutive 0s should have a 1 stuff bit inserted
    raw = [0, 0, 0, 0, 0]
    stuffed, count = apply_dynamic_bit_stuffing(raw)
    assert count == 1
    assert stuffed == [0, 0, 0, 0, 0, 1]

    destuffed, rem_count, err = remove_dynamic_bit_stuffing(stuffed)
    assert err is False
    assert rem_count == 1
    assert destuffed == raw


def test_bit_stuffing_violation_detection():
    # 6 consecutive 1s without stuff bit should trigger stuff error
    corrupted = [1, 1, 1, 1, 1, 1]
    _, _, err = remove_dynamic_bit_stuffing(corrupted)
    assert err is True


def test_round_trip_random_bits():
    import random
    rng = random.Random(42)
    raw = [rng.randint(0, 1) for _ in range(200)]
    stuffed, count = apply_dynamic_bit_stuffing(raw)
    destuffed, rem_count, err = remove_dynamic_bit_stuffing(stuffed)
    assert err is False
    assert rem_count == count
    assert destuffed == raw
