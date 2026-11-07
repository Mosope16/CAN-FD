"""Integer Feature Extraction Pipeline.

Integrates frame monitoring, sliding-window rate tracking, and missing-frame
deadline supervision into integer feature vectors (NumPy int64 arrays).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import numpy as np

from src.generator.message_definitions import MessageDefinition, load_network_config
from src.generator.traffic_generator import CANFDFrame
from src.monitor.frame_monitor import FrameMonitor
from src.monitor.protocol_monitor import ProtocolMonitor
from src.features.frame_features import CANFDFeatures, FEATURE_NAMES
from src.features.window_features import SlidingWindowAggregator


class FeaturePipeline:
    """Extracts integer feature vectors from CAN-FD traffic streams."""

    def __init__(
        self,
        network_config_path: str,
        window_duration_ms: int = 50,
        deadline_factor: float = 1.5,
        history_buffer_size: int = 1000,
    ) -> None:
        self.network_defs = load_network_config(network_config_path)
        window_duration_us = window_duration_ms * 1000

        self.frame_monitor = FrameMonitor(self.network_defs, history_buffer_size=history_buffer_size)
        self.protocol_monitor = ProtocolMonitor(
            self.network_defs,
            deadline_factor=deadline_factor,
            window_duration_us=window_duration_us,
        )
        self.sliding_window = SlidingWindowAggregator(window_duration_us=window_duration_us)

    def process_trace(
        self,
        frames: list[CANFDFrame],
    ) -> tuple[np.ndarray, np.ndarray, list[int]]:
        """Process chronological frame sequence and generate integer feature matrix.

        Returns:
            (X, y, timestamps_us):
            X: 2D NumPy array of shape (N, 14), dtype=int64
            y: 1D NumPy array of shape (N,), dtype=int64
            timestamps_us: List of simulation timestamps in microseconds
        """
        if not frames:
            return np.empty((0, len(FEATURE_NAMES)), dtype=np.int64), np.empty(0, dtype=np.int64), []

        # Initialize protocol deadline supervisor
        self.protocol_monitor.initialize_deadlines(frames[0].timestamp_us)

        features_data: list[list[int]] = []
        labels: list[int] = []
        timestamps: list[int] = []

        for frame in frames:
            t_us = frame.timestamp_us

            # 1. Check for expired deadlines (message suppression events)
            expired_ids = self.protocol_monitor.check_deadlines(t_us)
            for exp_id in expired_ids:
                mdef = self.network_defs.get(exp_id)
                expected_p = mdef.period_ms * 1000 if mdef else 50_000
                last_seen = self.protocol_monitor.last_seen_us.get(exp_id, t_us)
                elapsed = t_us - last_seen
                dev = elapsed - expected_p

                proto_errs, missing_cnt = self.protocol_monitor.get_window_counts(t_us)

                supp_feat = CANFDFeatures(
                    frame_id=exp_id,
                    frame_dlc=mdef.dlc if mdef else 8,
                    payload_delta=0,
                    inter_arrival=elapsed,
                    period_deviation=dev,
                    id_rate=0,
                    total_bus_rate=len(self.sliding_window.bus_timestamps),
                    id_seen_before=1 if exp_id in self.network_defs else 0,
                    dlc_mismatch=0,
                    payload_change_count=0,
                    protocol_error_count=proto_errs,
                    missing_frame_count=missing_cnt,
                    replay_similarity=0,
                    duplicate_count=0,
                )
                features_data.append(supp_feat.to_list())
                labels.append(5)  # Class 5: Suppression
                timestamps.append(t_us)

            # 2. Extract per-frame atomic metrics
            (
                inter_arr,
                p_dev,
                p_delta,
                p_change,
                id_seen,
                dlc_mis,
                prev_data,
            ) = self.frame_monitor.update_frame(
                arbitration_id=frame.arbitration_id,
                timestamp_us=t_us,
                dlc=frame.dlc,
                data=frame.data,
            )

            # 3. Extract sliding window rates
            id_rate, bus_rate = self.sliding_window.add_frame(frame.arbitration_id, t_us)

            # 4. Extract replay similarity against history (O(1) hash check)
            hist_set = self.frame_monitor.historical_payload_set.get(frame.arbitration_id, set())
            sim, dups = self.sliding_window.compute_replay_metrics(frame.data, hist_set, prev_data)

            # 5. Extract protocol errors & missing counts in window
            proto_errs, missing_cnt = self.protocol_monitor.get_window_counts(t_us)

            # 6. Assemble complete feature vector
            feat = CANFDFeatures(
                frame_id=frame.arbitration_id,
                frame_dlc=frame.dlc,
                payload_delta=p_delta,
                inter_arrival=inter_arr,
                period_deviation=p_dev,
                id_rate=id_rate,
                total_bus_rate=bus_rate,
                id_seen_before=id_seen,
                dlc_mismatch=dlc_mis,
                payload_change_count=p_change,
                protocol_error_count=proto_errs,
                missing_frame_count=missing_cnt,
                replay_similarity=sim,
                duplicate_count=dups,
            )

            features_data.append(feat.to_list())
            labels.append(frame.label)
            timestamps.append(t_us)

            # 7. Update protocol monitor reception timestamp
            self.protocol_monitor.record_frame_arrival(frame.arbitration_id, t_us)

        X = np.array(features_data, dtype=np.int64)
        y = np.array(labels, dtype=np.int64)
        return X, y, timestamps
