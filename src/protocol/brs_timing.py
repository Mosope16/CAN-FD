"""CAN-FD Bit Rate Switch (BRS) Dual-Phase Bit Timing Model.

Models transmission timing across nominal (arbitration/control/ACK) and
high-speed data phases conforming to ISO 11898-1:2015.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BRSTimingModel:
    """Calculates transmission durations for dual-rate CAN-FD bit streams."""

    nominal_bitrate_bps: int = 500_000   # 500 kbps (2.0 us per bit)
    data_bitrate_bps: int = 2_000_000    # 2.0 Mbps (0.5 us per bit)
    sample_point_nominal: float = 0.80
    sample_point_data: float = 0.75

    @property
    def nominal_bit_time_ns(self) -> int:
        return int(1_000_000_000 // self.nominal_bitrate_bps)

    @property
    def data_bit_time_ns(self) -> int:
        return int(1_000_000_000 // self.data_bitrate_bps)

    def calculate_duration_us(
        self,
        nominal_bits: int,
        data_bits: int,
        brs_active: bool = True,
    ) -> float:
        """Calculate total physical transmission time in microseconds.

        Args:
            nominal_bits: Count of bits transmitted at nominal arbitration rate.
            data_bits: Count of bits transmitted during payload/CRC phase.
            brs_active: If False, data_bits are transmitted at nominal bitrate.

        Returns:
            Total frame duration in microseconds.
        """
        nominal_ns = nominal_bits * self.nominal_bit_time_ns
        if brs_active:
            data_ns = data_bits * self.data_bit_time_ns
        else:
            data_ns = data_bits * self.nominal_bit_time_ns

        total_ns = nominal_ns + data_ns
        return total_ns / 1000.0
