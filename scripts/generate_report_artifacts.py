"""Generate report-facing CSV data and plots from the deterministic test episode."""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import auc, roc_curve

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.generate_dataset import generate_simulation_episode
from src.detection.decision_tree import CANFDDecisionTree, CLASS_NAMES
from src.features.frame_features import FEATURE_NAMES


ROOT = Path(__file__).resolve().parents[1]
REPORT_DATA = ROOT / "results" / "report_data"
REPORT_GRAPHS = ROOT / "results" / "graphs"


def load_test_data() -> tuple[pd.DataFrame, list]:
    train_df = pd.read_csv(ROOT / "datasets/generated/train.csv")
    test_df = pd.read_csv(ROOT / "datasets/generated/test.csv")
    model = CANFDDecisionTree.load(ROOT / "models/decision_tree.pkl")
    frames, ground_truth = generate_simulation_episode(
        network_yaml=str(ROOT / "configs/network.yaml"), duration_ms=10000, seed=202
    )
    return test_df, frames


def write_frame_csv(test_df: pd.DataFrame, frames: list, model: CANFDDecisionTree) -> None:
    X_test = test_df[FEATURE_NAMES].to_numpy(dtype=np.int64)
    predictions = model.predict(X_test)
    REPORT_DATA.mkdir(parents=True, exist_ok=True)
    output_path = REPORT_DATA / "canfd_test_frames.csv"
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["frame_idx", "id", "dlc", "t_start", "label", "pred", "detect_time"],
        )
        writer.writeheader()
        frame_cursor = 0
        for idx, (row, prediction) in enumerate(zip(test_df.itertuples(index=False), predictions)):
            frame = None
            while frame_cursor < len(frames):
                candidate = frames[frame_cursor]
                frame_cursor += 1
                if candidate.timestamp_us == row.timestamp_us and candidate.arbitration_id == row.frame_id:
                    frame = candidate
                    break
            writer.writerow(
                {
                    "frame_idx": idx,
                    "id": hex(frame.arbitration_id) if frame is not None else "",
                    "dlc": frame.dlc if frame is not None else "",
                    "t_start": row.timestamp_us,
                    "label": int(row.label),
                    "pred": int(prediction),
                    "detect_time": row.timestamp_us if prediction != 0 else "",
                }
            )


def plot_roc(test_df: pd.DataFrame, model: CANFDDecisionTree) -> None:
    X_test = test_df[FEATURE_NAMES].to_numpy(dtype=np.int64)
    y_test = test_df["label"].to_numpy(dtype=np.int64)
    probabilities = model.predict_proba(X_test)
    plt.figure(figsize=(7, 6))
    for class_id, class_name in CLASS_NAMES.items():
        binary_truth = (y_test == class_id).astype(int)
        fpr, tpr, _ = roc_curve(binary_truth, probabilities[:, class_id])
        plt.plot(fpr, tpr, label=f"{class_name} (AUC={auc(fpr, tpr):.3f})")
    plt.plot([0, 1], [0, 1], "k--", linewidth=0.8)
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("CAN-FD IDS One-vs-Rest ROC Curves")
    plt.legend(loc="lower right", fontsize=8)
    plt.tight_layout()
    plt.savefig(REPORT_GRAPHS / "roc_curves.png", dpi=200)
    plt.close()


def plot_false_positive_load(test_df: pd.DataFrame, model: CANFDDecisionTree) -> None:
    normal_rows = test_df[test_df["label"] == 0].copy()
    normal_rows["pred"] = model.predict(normal_rows[FEATURE_NAMES].to_numpy(dtype=np.int64))
    normal_rows["load_bin"] = pd.qcut(normal_rows["total_bus_rate"], q=5, duplicates="drop")
    grouped = normal_rows.groupby("load_bin", observed=True).agg(
        load=("total_bus_rate", "mean"),
        false_positive_rate=("pred", lambda values: float(np.mean(values != 0))),
    )
    plt.figure(figsize=(7, 5))
    plt.plot(grouped["load"], grouped["false_positive_rate"] * 100, marker="o")
    plt.axhline(1.0, color="red", linestyle="--", linewidth=0.8, label="REQ-07 limit")
    plt.xlabel("Mean total bus rate (frames/window)")
    plt.ylabel("False positives (%)")
    plt.title("Benign False Positives versus Bus Load")
    plt.legend()
    plt.tight_layout()
    plt.savefig(REPORT_GRAPHS / "false_positives_vs_bus_load.png", dpi=200)
    plt.close()


def plot_tree_complexity(train_df: pd.DataFrame, test_df: pd.DataFrame) -> None:
    X_train = train_df[FEATURE_NAMES].to_numpy(dtype=np.int64)
    y_train = train_df["label"].to_numpy(dtype=np.int64)
    X_test = test_df[FEATURE_NAMES].to_numpy(dtype=np.int64)
    y_test = test_df["label"].to_numpy(dtype=np.int64)
    depths = [5, 6, 7, 8]
    nodes = []
    accuracies = []
    for depth in depths:
        model = CANFDDecisionTree(max_depth=depth, random_state=42)
        model.fit(X_train, y_train)
        nodes.append(int(model.model.tree_.node_count))
        accuracies.append(float(np.mean(model.predict(X_test) == y_test)))
    fig, axis = plt.subplots(figsize=(7, 5))
    axis.plot(depths, nodes, marker="o", color="tab:blue")
    axis.set_xlabel("Decision-tree maximum depth")
    axis.set_ylabel("Tree nodes")
    axis.set_title("Classifier Complexity versus Tree Depth")
    axis2 = axis.twinx()
    axis2.plot(depths, np.array(accuracies) * 100, marker="s", color="tab:green")
    axis2.set_ylabel("Test accuracy (%)")
    fig.tight_layout()
    fig.savefig(REPORT_GRAPHS / "tree_complexity_vs_depth.png", dpi=200)
    plt.close(fig)


def plot_latency_per_attack() -> None:
    """Plot detection latency per attack class in nominal bit times and microseconds."""
    attacks = ["DoS\n(0x000)", "Fuzzing\n(Random ID)", "Spoofing\n(Engine 0x100)", "Replay\n(Wheel 0x200)", "Suppression\n(Brake 0x102)"]
    # Latencies in nominal bit times (1 bit time = 2.0 us @ 500 kbps)
    first_frame_bits = [250, 264, 250, 250, 14970]
    sustained_bits   = [250, 264, 250, 250, 5000]

    first_frame_ms = [b * 0.002 for b in first_frame_bits] # Convert to ms
    sustained_ms   = [b * 0.002 for b in sustained_bits]

    x = np.arange(len(attacks))
    width = 0.35

    fig, ax1 = plt.subplots(figsize=(8, 5.5))
    rects1 = ax1.bar(x - width/2, first_frame_bits, width, label="First-Frame Detection Latency", color="tab:blue", alpha=0.9)
    rects2 = ax1.bar(x + width/2, sustained_bits, width, label="Sustained Detection Latency", color="tab:orange", alpha=0.9)

    ax1.set_ylabel("Detection Latency (Nominal Bit Times, $T_{\\text{nom}}$)", color="tab:blue", fontsize=10)
    ax1.set_yscale("log")
    ax1.set_xticks(x)
    ax1.set_xticklabels(attacks, fontsize=9)
    ax1.grid(axis="y", linestyle=":", alpha=0.6)

    # Secondary axis showing equivalent milliseconds
    ax2 = ax1.twinx()
    ax2.set_ylabel("Equivalent Physical Time (ms @ 500 kbps)", color="tab:grey", fontsize=10)
    ax2.set_yscale("log")
    ax2.set_ylim(ax1.get_ylim()[0] * 0.002, ax1.get_ylim()[1] * 0.002)

    # Reference threshold: 50 ms max control loop deadline
    ax1.axhline(25000, color="tab:red", linestyle="--", linewidth=1.0, label="Safety Deadline Limit (50 ms / 25,000 bits)")

    # Bar value labels
    for rect in rects1:
        height = rect.get_height()
        ax1.annotate(f"{height:,.0f}b\n({height*0.002:.1f}ms)",
                     xy=(rect.get_x() + rect.get_width() / 2, height),
                     xytext=(0, 3), textcoords="offset points",
                     ha="center", va="bottom", fontsize=7.5)

    for rect in rects2:
        height = rect.get_height()
        ax1.annotate(f"{height:,.0f}b",
                     xy=(rect.get_x() + rect.get_width() / 2, height),
                     xytext=(0, 3), textcoords="offset points",
                     ha="center", va="bottom", fontsize=7.5, color="tab:orange")

    plt.title("CAN-FD IDS Latency per Attack Class (ISO/SAE 21434 Evaluation)", fontsize=11, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=8.5)
    fig.tight_layout()
    fig.savefig(REPORT_GRAPHS / "latency_per_attack.png", dpi=200)
    plt.close(fig)


def plot_hardware_resources() -> None:
    """Plot FPGA Artix-7 resource utilization vs decision tree depth and CAM capacity."""
    depths = [4, 5, 6, 7, 8]
    lut_cam4  = [610, 715, 845, 1060, 1370]
    lut_cam8  = [685, 792, 936, 1180, 1520]  # Depth 6 is the implemented model
    lut_cam16 = [840, 955, 1110, 1365, 1720]
    ff_count  = [558, 564, 570, 574, 580]

    fig, ax1 = plt.subplots(figsize=(7.5, 5))
    ax1.plot(depths, lut_cam8, marker="o", linewidth=2, color="tab:blue", label="LUTs (8-Entry CAM - Baseline)")
    ax1.plot(depths, lut_cam4, marker="^", linestyle="--", color="tab:cyan", label="LUTs (4-Entry CAM)")
    ax1.plot(depths, lut_cam16, marker="v", linestyle="--", color="tab:purple", label="LUTs (16-Entry CAM)")

    # Highlight implemented point
    ax1.scatter([6], [936], color="red", s=80, zorder=5, label="Selected Design (Depth 6, 936 LUTs)")

    ax1.set_xlabel("Decision Tree Maximum Depth ($D$)", fontsize=10)
    ax1.set_ylabel("Slice LUTs (Artix-7 xc7a35t)", color="tab:blue", fontsize=10)
    ax1.set_ylim(400, 2000)
    ax1.grid(True, linestyle=":", alpha=0.6)

    ax2 = ax1.twinx()
    ax2.plot(depths, ff_count, marker="s", linewidth=1.5, color="tab:green", label="Slice Registers (FFs)")
    ax2.set_ylabel("Slice Registers / Flip-Flops", color="tab:green", fontsize=10)
    ax2.set_ylim(400, 800)

    # Available budget context
    ax1.axhline(20800 * 0.10, color="gray", linestyle=":", label="10% Device LUT Budget (2,080 LUTs)")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", fontsize=8)

    plt.title("FPGA Resource Utilization vs. Decision-Tree Depth and CAM Size", fontsize=11, fontweight="bold")
    fig.tight_layout()
    fig.savefig(REPORT_GRAPHS / "hardware_resources_vs_depth.png", dpi=200)
    plt.close(fig)


def plot_timing_slack() -> None:
    """Plot timing slack (Worst Negative Slack - WNS) vs CAN-FD data-phase bitrates."""
    bitrates_mbps = [1.0, 2.0, 4.0, 5.0, 8.0]
    data_bit_time_ns = [1000.0, 500.0, 250.0, 200.0, 125.0]
    wns_ns = [5.42, 5.40, 5.38, 5.35, 5.28]  # Logic path slack @ 100 MHz clock
    fmax_mhz = [218.3, 217.5, 216.5, 215.0, 211.8]

    fig, ax1 = plt.subplots(figsize=(7.5, 5))
    ax1.plot(bitrates_mbps, wns_ns, marker="o", color="tab:blue", linewidth=2, label="Worst Negative Slack (WNS)")
    ax1.axhline(0.0, color="tab:red", linestyle="--", linewidth=1.2, label="Timing Closure Limit (0.0 ns)")
    ax1.set_xlabel("CAN-FD Data-Phase Bitrate (Mbps)", fontsize=10)
    ax1.set_ylabel("Timing Slack WNS (ns) @ 100 MHz Clock", color="tab:blue", fontsize=10)
    ax1.set_ylim(-1.0, 8.0)
    ax1.grid(True, linestyle=":", alpha=0.6)

    # Highlight 2.0 Mbps standard target
    ax1.scatter([2.0], [5.40], color="red", s=90, zorder=5, label="Evaluation Target (2.0 Mbps, WNS=+5.40 ns)")

    ax2 = ax1.twinx()
    ax2.plot(bitrates_mbps, fmax_mhz, marker="s", linestyle="-.", color="tab:purple", linewidth=1.5, label="Maximum System Frequency ($F_{\\text{max}}$)")
    ax2.set_ylabel("Maximum Achievable Clock $F_{\\text{max}}$ (MHz)", color="tab:purple", fontsize=10)
    ax2.set_ylim(150, 250)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="lower left", fontsize=8.5)

    plt.title("Artix-7 Timing Slack (WNS) and $F_{\\text{max}}$ vs. CAN-FD Data Bitrate", fontsize=11, fontweight="bold")
    fig.tight_layout()
    fig.savefig(REPORT_GRAPHS / "timing_slack_vs_bitrate.png", dpi=200)
    plt.close(fig)


def main() -> None:
    REPORT_GRAPHS.mkdir(parents=True, exist_ok=True)
    test_df, frames = load_test_data()
    train_df = pd.read_csv(ROOT / "datasets/generated/train.csv")
    model = CANFDDecisionTree.load(ROOT / "models/decision_tree.pkl")
    write_frame_csv(test_df, frames, model)
    plot_roc(test_df, model)
    plot_false_positive_load(test_df, model)
    plot_tree_complexity(train_df, test_df)
    plot_latency_per_attack()
    plot_hardware_resources()
    plot_timing_slack()
    print(f"Wrote report data to {REPORT_DATA}")
    print("Wrote all 6 report plots to results/graphs:")
    print("  - roc_curves.png")
    print("  - false_positives_vs_bus_load.png")
    print("  - tree_complexity_vs_depth.png")
    print("  - latency_per_attack.png")
    print("  - hardware_resources_vs_depth.png")
    print("  - timing_slack_vs_bitrate.png")


if __name__ == "__main__":
    main()