"""CAN-FD Dynamic Bit Stuffing Engine.

Implements standard dynamic bit-stuffing rules (inserting inverse bit after
5 consecutive identical bits) and receiver destuffing validation conforming
to ISO 11898-1:2015.
"""

from __future__ import annotations

from typing import List, Tuple


def apply_dynamic_bit_stuffing(raw_bits: list[int]) -> tuple[list[int], int]:
    """Insert dynamic stuff bits after every 5 consecutive identical bits.

    Args:
        raw_bits: Unstuffed input bits (SOF through Data Field).

    Returns:
        (stuffed_bits, stuff_count): The bit sequence with stuff bits inserted,
        and the total count of stuff bits added.
    """
    if not raw_bits:
        return [], 0

    stuffed: list[int] = []
    consecutive = 0
    last_bit = -1
    stuff_count = 0

    for bit in raw_bits:
        stuffed.append(bit)
        if bit == last_bit:
            consecutive += 1
            if consecutive == 5:
                # Insert stuff bit of opposite polarity
                stuff_bit = 1 - bit
                stuffed.append(stuff_bit)
                stuff_count += 1
                consecutive = 1
                last_bit = stuff_bit
        else:
            consecutive = 1
            last_bit = bit

    return stuffed, stuff_count


def remove_dynamic_bit_stuffing(stuffed_bits: list[int]) -> tuple[list[int], int, bool]:
    """Destuff a bit sequence and detect dynamic bit-stuffing violations.

    Whenever 5 consecutive identical bits are detected in the received stream,
    the immediately following bit is verified as an inverse stuff bit and removed.

    Args:
        stuffed_bits: Dynamically stuffed bit sequence.

    Returns:
        (destuffed_bits, stuff_count, has_stuff_error):
        destuffed_bits: The original unstuffed bit sequence.
        stuff_count: Total number of valid stuff bits removed.
        has_stuff_error: True if 6 consecutive identical bits were encountered.
    """
    if not stuffed_bits:
        return [], 0, False

    destuffed: list[int] = []
    consecutive = 0
    last_bit = -1
    stuff_count = 0
    has_stuff_error = False

    i = 0
    n = len(stuffed_bits)
    while i < n:
        bit = stuffed_bits[i]
        destuffed.append(bit)

        if bit == last_bit:
            consecutive += 1
            if consecutive == 5:
                # The next bit in the stream must be a stuff bit of opposite polarity
                if i + 1 < n:
                    next_bit = stuffed_bits[i + 1]
                    if next_bit == bit:
                        # 6 consecutive identical bits -> STUFF ERROR!
                        has_stuff_error = True
                        break
                    else:
                        # Valid stuff bit: discard it from payload
                        stuff_count += 1
                        i += 1  # Advance past stuff bit
                        # The stuff bit was present on the physical bus, so it starts
                        # a new consecutive sequence of length 1 with value next_bit
                        consecutive = 1
                        last_bit = next_bit
                else:
                    # Stream ended right after 5 bits without expected stuff bit
                    break
        else:
            consecutive = 1
            last_bit = bit

        i += 1

    return destuffed, stuff_count, has_stuff_error
