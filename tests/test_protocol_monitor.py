"""Tests for Protocol Supervisory Monitor and Deadline Enforcement.

Validates sliding window error counting, timestamp pruning, and missing message
deadline monitoring against automotive DBC definitions.
"""

from __future__ import annotations

import pytest

from src.generator.message_definitions import load_network_config
from src.monitor.protocol_monitor import ProtocolMonitor


@pytest.fixture
def sample_defs():
    return load_network_config("configs/network.yaml")


def test_deadline_initialization_and_expiration(sample_defs) -> None:
    """Verify arrival deadline tracking and expiration on silence."""
    mon = ProtocolMonitor(network_defs=sample_defs, deadline_factor=1.5, window_duration_us=100_000)

    # 0x102 (BrakeStatus) has nominal period of 20 ms (20,000 us)
    # Deadline factor is 1.5 -> expected deadline is 30,000 us from first frame
    mon.record_frame_arrival(0x102, 10_000)
    assert mon.next_deadline_us[0x102] == 10_000 + int(1.5 * 20_000)  # 40,000 us

    # Check at 35,000 us -> not yet expired
    expired = mon.check_deadlines(35_000)
    assert 0x102 not in expired

    # Check at 40,001 us -> deadline expired!
    expired = mon.check_deadlines(40_001)
    assert 0x102 in expired

    # Next deadline should have advanced by one full period (20,000 us -> 60,000 us)
    assert mon.next_deadline_us[0x102] == 40_000 + 20_000


def test_sliding_window_error_pruning(sample_defs) -> None:
    """Verify that protocol errors outside the window are cleanly pruned."""
    window_us = 100_000  # 100 ms
    mon = ProtocolMonitor(network_defs=sample_defs, window_duration_us=window_us)

    # Record errors at 10 ms, 50 ms, 90 ms
    mon.record_protocol_error(10_000)
    mon.record_protocol_error(50_000)
    mon.record_protocol_error(90_000)

    # Query at 95 ms -> all 3 are within [0, 100 ms]
    err_cnt, _ = mon.get_window_counts(95_000)
    assert err_cnt == 3

    # Query at 120 ms -> 10 ms error is older than cutoff (120 - 100 = 20 ms), so pruned
    err_cnt, _ = mon.get_window_counts(120_000)
    assert err_cnt == 2

    # Query at 250 ms -> all old errors pruned
    err_cnt, _ = mon.get_window_counts(250_000)
    assert err_cnt == 0
