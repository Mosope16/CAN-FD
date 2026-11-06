"""Unit tests for Attack Engines and Ground Truth Tracking."""

import pytest
from src.attacks.dos import DoSAttack
from src.attacks.fuzzing import FuzzingAttack
from src.attacks.replay import ReplayAttack
from src.attacks.spoofing import SpoofingAttack
from src.attacks.suppression import SuppressionAttack
from src.attacks.ground_truth import GroundTruthManager
from src.generator.traffic_generator import CANFDFrame


def test_dos_attack_rate_and_labels():
    dos = DoSAttack(start_ms=100, duration_ms=20, target_id=0x050, interval_us=500)
    frames = dos.generate_frames()
    # 20 ms / 0.5 ms = 40 frames
    assert len(frames) == 40
    assert all(f.label == 1 for f in frames)
    assert all(f.arbitration_id == 0x050 for f in frames)
    assert frames[0].timestamp_us == 100_000
    assert frames[-1].timestamp_us == 119_500


def test_fuzzing_attack_randomness():
    fuzz = FuzzingAttack(start_ms=50, duration_ms=10, interval_us=1000, seed=42)
    frames = fuzz.generate_frames()
    assert len(frames) == 10
    assert all(f.label == 2 for f in frames)
    # Check that IDs vary
    ids = set(f.arbitration_id for f in frames)
    assert len(ids) > 1


def test_spoofing_attack():
    spoof = SpoofingAttack(
        start_ms=200,
        duration_ms=50,
        target_id=0x102,
        interval_us=5000,
        spoofed_payload=b"\xFF\x00\xFF\x00\x00\x00\x00\x00",
    )
    frames = spoof.generate_frames()
    assert len(frames) == 10
    assert all(f.label == 3 for f in frames)
    assert all(f.arbitration_id == 0x102 for f in frames)


def test_replay_attack():
    baseline = [
        CANFDFrame(timestamp_us=1000, arbitration_id=0x103, dlc=8, data=b"frame1"),
        CANFDFrame(timestamp_us=2000, arbitration_id=0x103, dlc=8, data=b"frame2"),
        CANFDFrame(timestamp_us=3000, arbitration_id=0x100, dlc=8, data=b"other"),
    ]
    replay = ReplayAttack.capture_and_schedule(
        frames_pool=baseline,
        target_id=0x103,
        capture_start_ms=0,
        capture_duration_ms=5,
        replay_start_ms=10,
    )
    replayed = replay.generate_frames()
    assert len(replayed) == 2
    assert all(f.label == 4 for f in replayed)
    assert replayed[0].data == b"frame1"
    assert replayed[1].data == b"frame2"
    assert replayed[0].timestamp_us == 10_000
    assert replayed[1].timestamp_us == 11_000


def test_suppression_window():
    supp = SuppressionAttack(target_id=0x101, start_ms=100, duration_ms=200)
    assert supp.is_suppressed(0x101, 99_999) is False
    assert supp.is_suppressed(0x101, 150_000) is True
    assert supp.is_suppressed(0x101, 300_000) is False
    assert supp.is_suppressed(0x102, 150_000) is False
