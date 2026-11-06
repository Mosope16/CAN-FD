"""Unit tests for Message Definitions and Traffic Generator."""

import pytest
from src.generator.message_definitions import (
    MessageDefinition,
    SignalDefinition,
    bytes_to_dlc,
    dlc_to_bytes,
    load_network_config,
)
from src.generator.traffic_generator import TrafficGenerator


def test_dlc_conversion():
    assert dlc_to_bytes(0) == 0
    assert dlc_to_bytes(8) == 8
    assert dlc_to_bytes(9) == 12
    assert dlc_to_bytes(10) == 16
    assert dlc_to_bytes(13) == 32
    assert dlc_to_bytes(15) == 64

    assert bytes_to_dlc(0) == 0
    assert bytes_to_dlc(8) == 8
    assert bytes_to_dlc(12) == 9
    assert bytes_to_dlc(16) == 10
    assert bytes_to_dlc(32) == 13
    assert bytes_to_dlc(64) == 15


def test_signal_encode_decode():
    sig = SignalDefinition(
        name="speed_kph",
        start_byte=0,
        num_bytes=2,
        min_val=0.0,
        max_val=250.0,
        scale=0.01,
        offset=0.0,
    )
    raw = sig.encode(123.45)
    assert len(raw) == 2
    decoded = sig.decode(raw)
    assert pytest.approx(decoded, abs=0.02) == 123.45


def test_network_config_loader():
    defs = load_network_config("configs/network.yaml")
    assert 0x100 in defs
    assert 0x101 in defs
    assert 0x102 in defs
    assert 0x103 in defs
    assert 0x200 in defs
    assert 0x201 in defs
    assert defs[0x100].period_ms == 10
    assert defs[0x100].dlc == 8


def test_traffic_generator_determinism():
    gen1 = TrafficGenerator("configs/network.yaml", seed=42)
    trace1 = gen1.generate_trace(duration_ms=1000)

    gen2 = TrafficGenerator("configs/network.yaml", seed=42)
    trace2 = gen2.generate_trace(duration_ms=1000)

    assert len(trace1) == len(trace2)
    assert len(trace1) > 0
    for f1, f2 in zip(trace1, trace2):
        assert f1.timestamp_us == f2.timestamp_us
        assert f1.arbitration_id == f2.arbitration_id
        assert f1.dlc == f2.dlc
        assert f1.data == f2.data
        assert f1.label == f2.label
