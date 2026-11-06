"""Automotive Signal Dynamics and Physics Models.

Generates realistic continuous physical signals (powertrain, thermal, brake,
steering, and battery telemetry) with deterministic mathematical formulations.
"""

from __future__ import annotations

import math
import random
from typing import Dict, Any


class SignalGenerator:
    """Generates continuous physical signals for automotive ECUs over simulation time."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self.seed = seed
        self._counter_100 = 0
        self._odometer_km = 12450.0

    def generate_signals(self, time_us: int) -> dict[int, dict[str, float]]:
        """Compute the instantaneous physical signals for all configured messages.

        Args:
            time_us: Current simulation timestamp in integer microseconds.

        Returns:
            Mapping of CAN ID to dictionary of signal name -> physical value.
        """
        t_sec = time_us / 1_000_000.0

        # --- 0x100: VehicleSpeed ---
        # Smooth driving cycle: 0-3s: accel to 60kph, 3-7s: cruise with slight oscillation, 7-10s: braking
        base_speed = 50.0 + 20.0 * math.sin(0.4 * t_sec) + 5.0 * math.cos(1.2 * t_sec)
        jitter_speed = (self.rng.random() - 0.5) * 0.4
        speed_kph = max(0.0, min(220.0, base_speed + jitter_speed))

        # Acceleration is derivative of speed (mps^2)
        accel_mps2 = 2.5 * math.cos(0.4 * t_sec) * (1000.0 / 3600.0)
        self._counter_100 = (self._counter_100 + 1) & 0xFF
        # Simple checksum: byte XOR approximation
        chk = (int(speed_kph * 10) ^ int(abs(accel_mps2) * 100) ^ self._counter_100) & 0xFF

        vehicle_speed_signals = {
            "speed_kph": round(speed_kph, 2),
            "acceleration_mps2": round(accel_mps2, 3),
            "counter": float(self._counter_100),
            "checksum": float(chk),
        }

        # --- 0x101: EngineTemp ---
        # Warmup curve: asymptotic approach to 90 degC
        coolant = 75.0 + 15.0 * (1.0 - math.exp(-t_sec / 8.0)) + (self.rng.random() - 0.5) * 0.2
        oil = coolant + 5.0 * (1.0 - math.exp(-t_sec / 12.0))
        fan_duty = 40.0 if coolant > 88.0 else 10.0
        engine_temp_signals = {
            "coolant_temp_c": round(coolant, 1),
            "oil_temp_c": round(oil, 1),
            "fan_duty_pct": round(fan_duty, 0),
        }

        # --- 0x102: BrakeStatus ---
        # Periodic braking events around t=3.5s and t=7.5s
        brake_event_1 = math.exp(-((t_sec - 3.5) ** 2) / 0.3)
        brake_event_2 = math.exp(-((t_sec - 7.5) ** 2) / 0.4)
        pedal_pos = min(100.0, (brake_event_1 * 45.0) + (brake_event_2 * 80.0))
        pressure_bar = pedal_pos * 1.8 + (self.rng.random() - 0.5) * 1.0
        pressure_bar = max(0.0, min(220.0, pressure_bar))
        abs_active = 1.0 if pressure_bar > 120.0 else 0.0
        brake_signals = {
            "pedal_pos_pct": round(pedal_pos, 1),
            "pressure_bar": round(pressure_bar, 1),
            "abs_active": abs_active,
        }

        # --- 0x103: SteeringAngle ---
        # Gentle curve maneuvers
        angle_deg = 35.0 * math.sin(0.8 * t_sec) + 8.0 * math.cos(2.1 * t_sec)
        rot_rate_dps = 28.0 * math.cos(0.8 * t_sec) - 16.8 * math.sin(2.1 * t_sec)
        steering_signals = {
            "angle_deg": round(angle_deg, 1),
            "rot_rate_dps": round(rot_rate_dps, 1),
        }

        # --- 0x200: BatteryStatus ---
        soc_pct = max(10.0, 85.0 - (t_sec * 0.05))
        current_a = -30.0 + 50.0 * math.sin(0.5 * t_sec)
        voltage_v = 400.0 - (current_a * 0.05)
        max_cell_temp = 28.0 + (t_sec * 0.02)
        battery_signals = {
            "state_of_charge_pct": round(soc_pct, 2),
            "voltage_v": round(voltage_v, 1),
            "current_a": round(current_a, 1),
            "max_cell_temp_c": round(max_cell_temp, 0),
        }

        # --- 0x201: VehicleDiagnostics ---
        self._odometer_km += (speed_kph / 3600.0) * 0.01
        diag_signals = {
            "dtc_count": 0.0,
            "odometer_km": round(self._odometer_km, 1),
        }

        return {
            0x100: vehicle_speed_signals,
            0x101: engine_temp_signals,
            0x102: brake_signals,
            0x103: steering_signals,
            0x200: battery_signals,
            0x201: diag_signals,
        }
