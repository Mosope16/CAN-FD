"""CAN-FD Bit-Stream Frame Decoder and Protocol State Machine.

Conforms to ISO 11898-1:2015 state machine:
1. Dynamic bit destuffing from SOF through end of Data Field.
2. Fixed-stuff bit validation and Stuff Count check across CRC Field.
3. Form validation on CRC Delimiter, ACK Delimiter, and End of Frame.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from src.generator.message_definitions import bytes_to_dlc, dlc_to_bytes
from src.generator.traffic_generator import CANFDFrame
from src.protocol.crc_engine import (
    CRC17_LEN,
    CRC17_POLY,
    CRC21_LEN,
    CRC21_POLY,
    bit_list_to_int,
    compute_crc,
)
from src.protocol.crc_field_encoder import decode_and_validate_crc_field


@dataclass
class ProtocolValidationReport:
    """Detailed protocol diagnostics for a decoded frame."""

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    dynamic_stuff_error: bool = False
    fixed_stuff_error: bool = False
    stuff_count_parity_error: bool = False
    crc_mismatch: bool = False
    form_error: bool = False
    invalid_dlc_error: bool = False
    computed_crc: int = 0
    received_crc: int = 0
    decoded_stuff_count: int = 0


class FrameDecoder:
    """Decodes physical bit streams conforming to ISO CAN-FD framing rules."""

    @staticmethod
    def decode_stream(
        raw_bits: list[int],
        timestamp_us: int = 0,
    ) -> tuple[Optional[CANFDFrame], ProtocolValidationReport]:
        """Decode physical bit stream into a CANFDFrame and protocol report."""
        report = ProtocolValidationReport(is_valid=True)

        if len(raw_bits) < 30:
            report.is_valid = False
            report.errors.append("FRAME_TOO_SHORT")
            return None, report

        # Step 1: Check SOF (must be dominant 0)
        if raw_bits[0] != 0:
            report.is_valid = False
            report.form_error = True
            report.errors.append("SOF_VIOLATION")

        # Step 2: Bit-by-bit dynamic destuffing state machine
        # We need to parse Header (SOF, Arb, Control) to determine DLC and payload length
        destuffed_header_data: list[int] = []
        consecutive = 0
        last_bit = -1
        dynamic_stuff_count = 0
        raw_idx = 0
        n_raw = len(raw_bits)

        is_extended = False
        target_unstuffed_bits: Optional[int] = None
        dlc_val = 0
        arb_id = 0
        brs_bit = 1
        esi_bit = 0

        while raw_idx < n_raw:
            bit = raw_bits[raw_idx]
            destuffed_header_data.append(bit)

            # Check dynamic stuff rule
            if bit == last_bit:
                consecutive += 1
                if consecutive == 5:
                    # Next bit must be a stuff bit of opposite polarity
                    if raw_idx + 1 < n_raw:
                        next_bit = raw_bits[raw_idx + 1]
                        if next_bit == bit:
                            # 6 consecutive identical bits in dynamic zone -> STUFF ERROR!
                            report.is_valid = False
                            report.dynamic_stuff_error = True
                            report.errors.append("DYNAMIC_STUFF_ERROR")
                            break
                        else:
                            # Valid stuff bit: discard from destuffed data
                            dynamic_stuff_count += 1
                            raw_idx += 1
                            consecutive = 1
                            last_bit = next_bit
                    else:
                        break
            else:
                consecutive = 1
                last_bit = bit

            raw_idx += 1

            # Check if we have gathered enough bits to parse Control Field & DLC
            if target_unstuffed_bits is None:
                # Minimum header length:
                # Standard: SOF(1) + ID(11) + RRS(1) + IDE(1) + FDF(1) + res(1) + BRS(1) + ESI(1) + DLC(4) = 22 bits
                # Extended: SOF(1) + Base(11) + SRR(1) + IDE(1) + Ext(18) + RRS(1) + FDF(1) + res(1) + BRS(1) + ESI(1) + DLC(4) = 40 bits
                if len(destuffed_header_data) >= 15:
                    if destuffed_header_data[13] == 1:  # IDE bit for extended
                        is_extended = True

                if (not is_extended and len(destuffed_header_data) >= 22) or (
                    is_extended and len(destuffed_header_data) >= 40
                ):
                    # Parse header fields
                    p = 1
                    if not is_extended:
                        arb_id = bit_list_to_int(destuffed_header_data[p : p + 11])
                        p += 11 + 3  # skip ID, RRS, IDE, FDF
                    else:
                        base = bit_list_to_int(destuffed_header_data[p : p + 11])
                        p += 11 + 2  # Base, SRR, IDE
                        ext = bit_list_to_int(destuffed_header_data[p : p + 18])
                        arb_id = (base << 18) | ext
                        p += 18 + 2  # Ext, RRS, FDF

                    res_bit = destuffed_header_data[p]
                    p += 1
                    brs_bit = destuffed_header_data[p]
                    p += 1
                    esi_bit = destuffed_header_data[p]
                    p += 1
                    dlc_val = bit_list_to_int(destuffed_header_data[p : p + 4])
                    p += 4

                    if dlc_val > 15:
                        report.is_valid = False
                        report.invalid_dlc_error = True
                        report.errors.append("INVALID_DLC")
                        dlc_val = 15

                    payload_len = dlc_to_bytes(dlc_val)
                    header_bits = 22 if not is_extended else 40
                    target_unstuffed_bits = header_bits + (payload_len * 8)

            # Once we reach target_unstuffed_bits, dynamic bit stuffing terminates!
            if target_unstuffed_bits is not None and len(destuffed_header_data) >= target_unstuffed_bits:
                break

        # Extract payload bytes
        header_len = 22 if not is_extended else 40
        data_bits = destuffed_header_data[header_len:target_unstuffed_bits]
        payload = bytearray()
        for i in range(0, len(data_bits), 8):
            chunk = data_bits[i : i + 8]
            payload.append(bit_list_to_int(chunk))

        # Step 3: CRC Verification
        crc_len = CRC17_LEN if dlc_val <= 10 else CRC21_LEN
        crc_poly = CRC17_POLY if dlc_val <= 10 else CRC21_POLY
        unstuffed_body = destuffed_header_data[:target_unstuffed_bits]
        expected_crc = compute_crc(unstuffed_body, crc_poly, crc_len)
        report.computed_crc = expected_crc

        # Step 4: CRC Field validation
        last_bit_before_crc = raw_bits[raw_idx - 1] if raw_idx > 0 else 0
        crc_field_len = 1 + 4 + 1 + crc_len + (crc_len // 4) + 1  # includes fixed stuff bits and delimiter
        remaining_bits = raw_bits[raw_idx:]

        if len(remaining_bits) >= crc_field_len:
            crc_bits = remaining_bits[:crc_field_len]
            sc_val, rec_crc, fs_ok, parity_ok, delim_ok = decode_and_validate_crc_field(
                crc_bits, crc_len, last_bit_before_crc
            )
            report.received_crc = rec_crc
            report.decoded_stuff_count = sc_val

            if not fs_ok:
                report.is_valid = False
                report.fixed_stuff_error = True
                report.errors.append("FIXED_STUFF_ERROR")
            if not parity_ok:
                report.is_valid = False
                report.stuff_count_parity_error = True
                report.errors.append("STUFF_COUNT_PARITY_ERROR")
            if rec_crc != expected_crc:
                report.is_valid = False
                report.crc_mismatch = True
                report.errors.append("CRC_MISMATCH")
            if not delim_ok:
                report.is_valid = False
                report.form_error = True
                report.errors.append("CRC_DELIMITER_ERROR")

            # Step 5: ACK and EOF Validation
            ack_eof_bits = remaining_bits[crc_field_len:]
            if len(ack_eof_bits) >= 2:
                # ack_slot = ack_eof_bits[0]
                ack_delim = ack_eof_bits[1]
                if ack_delim != 1:
                    report.is_valid = False
                    report.form_error = True
                    report.errors.append("ACK_DELIMITER_ERROR")
        else:
            report.is_valid = False
            report.errors.append("TRUNCATED_CRC_FIELD")

        decoded_frame = CANFDFrame(
            timestamp_us=timestamp_us,
            arbitration_id=arb_id,
            dlc=dlc_val,
            data=bytes(payload),
            is_extended=is_extended,
            brs=(brs_bit == 1),
            esi=(esi_bit == 1),
            label=0,
            attack_name="Decoded",
        )

        return decoded_frame, report
