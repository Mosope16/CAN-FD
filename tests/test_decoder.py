"""Unit and integration tests for CAN-FD FrameBuilder, Decoder, and BitCorruptor."""

import pytest
from src.generator.traffic_generator import CANFDFrame
from src.protocol.bit_corruptor import BitCorruptor
from src.protocol.frame_builder import FrameBuilder
from src.protocol.frame_decoder import FrameDecoder
from src.protocol.validator import ProtocolValidator


def test_round_trip_crc17():
    # DLC=8 (8 bytes) -> CRC-17
    frame = CANFDFrame(
        timestamp_us=1000,
        arbitration_id=0x100,
        dlc=8,
        data=bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        is_extended=False,
        brs=True,
        esi=False,
    )
    bit_stream = FrameBuilder.serialize_frame(frame)
    decoded, report = FrameDecoder.decode_stream(bit_stream.bits, timestamp_us=1000)

    assert report.is_valid is True
    assert len(report.errors) == 0
    assert decoded is not None
    assert decoded.arbitration_id == frame.arbitration_id
    assert decoded.dlc == frame.dlc
    assert decoded.data == frame.data


def test_round_trip_crc21():
    # DLC=13 (32 bytes) -> CRC-21
    frame = CANFDFrame(
        timestamp_us=5000,
        arbitration_id=0x201,
        dlc=13,
        data=bytes(range(32)),
        is_extended=False,
        brs=True,
        esi=False,
    )
    bit_stream = FrameBuilder.serialize_frame(frame)
    decoded, report = FrameDecoder.decode_stream(bit_stream.bits, timestamp_us=5000)

    assert report.is_valid is True
    assert len(report.errors) == 0
    assert decoded is not None
    assert decoded.arbitration_id == frame.arbitration_id
    assert decoded.dlc == frame.dlc
    assert decoded.data == frame.data


def test_corrupt_crc_bit():
    frame = CANFDFrame(
        timestamp_us=2000,
        arbitration_id=0x102,
        dlc=8,
        data=b"\x01\x02\x03\x04\x05\x06\x07\x08",
    )
    bit_stream = FrameBuilder.serialize_frame(frame)
    corrupted_stream = BitCorruptor.corrupt_crc_bit(bit_stream, bit_offset_in_crc=2)
    decoded, report = FrameDecoder.decode_stream(corrupted_stream.bits)

    assert report.is_valid is False
    assert report.crc_mismatch is True
    assert "CRC_MISMATCH" in report.errors


def test_corrupt_fixed_stuff_bit():
    frame = CANFDFrame(
        timestamp_us=3000,
        arbitration_id=0x103,
        dlc=8,
        data=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
    )
    bit_stream = FrameBuilder.serialize_frame(frame)
    corrupted_stream = BitCorruptor.corrupt_fixed_stuff_bit(bit_stream, fixed_stuff_index=0)
    decoded, report = FrameDecoder.decode_stream(corrupted_stream.bits)

    assert report.is_valid is False
    assert report.fixed_stuff_error is True
    assert "FIXED_STUFF_ERROR" in report.errors


def test_corrupt_ack_delimiter():
    frame = CANFDFrame(
        timestamp_us=4000,
        arbitration_id=0x100,
        dlc=8,
        data=b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0",
    )
    bit_stream = FrameBuilder.serialize_frame(frame)
    corrupted_stream = BitCorruptor.corrupt_ack_delimiter(bit_stream)
    decoded, report = FrameDecoder.decode_stream(corrupted_stream.bits)

    assert report.is_valid is False
    assert "ACK_DELIMITER_ERROR" in report.errors


def test_invalid_dlc_rejected_at_logical_ingress():
    frame = CANFDFrame(
        timestamp_us=5000,
        arbitration_id=0x100,
        dlc=16,
        data=b"\x00" * 64,
    )

    with pytest.raises(ValueError, match="Invalid CAN-FD DLC"):
        FrameBuilder.serialize_frame(frame)

    report = ProtocolValidator.validate_dlc(0xFF)
    assert report.is_valid is False
    assert report.invalid_dlc_error is True
    assert "INVALID_DLC" in report.errors


def test_protocol_validator_tracking():
    validator = ProtocolValidator()
    frame = CANFDFrame(
        timestamp_us=1000,
        arbitration_id=0x100,
        dlc=8,
        data=b"\x00" * 8,
    )
    bit_stream = FrameBuilder.serialize_frame(frame)

    rep1 = validator.validate_stream(bit_stream.bits)
    assert rep1.is_valid is True
    assert validator.total_checked == 1
    assert validator.total_errors == 0

    corrupted = BitCorruptor.corrupt_crc_bit(bit_stream)
    rep2 = validator.validate_stream(corrupted.bits)
    assert rep2.is_valid is False
    assert validator.total_checked == 2
    assert validator.total_errors == 1
