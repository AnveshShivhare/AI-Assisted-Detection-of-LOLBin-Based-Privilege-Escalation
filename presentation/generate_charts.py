#!/usr/bin/env python3
"""
generate_charts.py
==================
Generates high-resolution academic charts for the M.Tech presentation slides.
All data strictly sourced from:
- evaluation/results/benchmark_report.md
- evaluation/results/evaluation_summary.json
- predict.py output on data/live-attack-benign.log
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

OUTPUT_DIR = "presentation/assets"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set high-DPI academic typography styling
plt.rcParams.update({
    "font.sans-serif": "DejaVu Sans",
    "font.family": "sans-serif",
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.titlesize": 13,
    "axes.edgecolor": "#CBD5E1",
    "axes.linewidth": 1.0,
    "grid.color": "#F1F5F9",
    "grid.linestyle": "--",
    "grid.linewidth": 0.8,
})


def generate_baseline_distribution_chart():
    """Chart for Slide 6: Real Baseline Score Distribution (7,649 held-out events)."""
    fig, ax = plt.subplots(figsize=(6.0, 4.3), dpi=300)
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FAFAFA")

    ranges = ["[0.0, 0.2)", "[0.2, 0.4)", "[0.4, 0.5)", "[0.5, 0.6)", "[0.6, 0.8)", "[0.8, 1.0]"]
    percentages = [87.36, 6.96, 1.02, 0.68, 1.39, 2.60]
    counts = [6682, 532, 78, 52, 106, 199]

    # Colors: Benign bins (navy/blue) vs Anomaly bins (orange/red above 0.5 threshold)
    colors = ["#1E3A8A", "#2563EB", "#60A5FA", "#F59E0B", "#EF4444", "#DC2626"]

    bars = ax.bar(ranges, percentages, color=colors, width=0.58, edgecolor="#0F172A", linewidth=0.8, zorder=3)

    # Annotate bar percentages and counts
    for bar, pct, cnt in zip(bars, percentages, counts):
        yval = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            yval + 1.8,
            f"{pct:.1f}%\n({cnt})",
            ha="center",
            va="bottom",
            fontsize=8,
            fontweight="bold",
            color="#1E293B"
        )

    # Threshold divider annotation between bin 2 and bin 3
    ax.axvline(2.5, color="#DC2626", linestyle="--", linewidth=1.5, zorder=4)
    ax.text(
        2.55,
        68,
        "Decision Boundary (0.50)\nBenign: 95.34% | FPR: 4.67%",
        color="#B91C1C",
        fontsize=8.5,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#FEE2E2", edgecolor="#DC2626", alpha=0.95),
        zorder=5
    )

    ax.set_ylim(0, 104)
    ax.set_ylabel("Percentage of Held-Out Events (%)", fontweight="bold", color="#1E293B")
    ax.set_xlabel("Isolation Forest Anomaly Score Bins", fontweight="bold", color="#1E293B")
    ax.set_title("Real Auditd Baseline Score Distribution (N=7,649)", fontweight="bold", color="#0F172A", pad=10)
    ax.grid(axis="y", zorder=0)

    plt.tight_layout()
    output_path = os.path.join(OUTPUT_DIR, "slide6_baseline_dist.png")
    plt.savefig(output_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"[+] Saved: {output_path}")


def generate_sliding_window_context_chart():
    """Chart for Slide 7: Real Executed Commands Anomaly Scores & 'id' Context Effect."""
    fig, ax = plt.subplots(figsize=(6.0, 4.3), dpi=300)
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FAFAFA")

    labels = [
        "tar checkpoint exec\n(GTFOBin, Event #96)",
        "sudo find -exec\n(GTFOBin, Event #44)",
        "sudo python3 exec\n(GTFOBin, Event #76)",
        "id (mid-sequence)\n(Post-hex shell, Event #106)",
        "id (mid-sequence)\n(Post-tar exec, Event #83)",
        "id (normal recon)\n(Post-whoami, Event #85)",
        "id (isolated)\n(Post-base64, Event #109)",
        "id (isolated)\n(Post-awk shell, Event #68)"
    ]
    scores = [0.9702, 0.8503, 0.8132, 0.5834, 0.5792, 0.1287, 0.0813, 0.0509]
    colors = [
        "#DC2626", "#DC2626", "#DC2626",  # GTFOBins (Flagged)
        "#EA580C", "#EA580C",              # id mid-sequence (Flagged via window!)
        "#10B981", "#10B981", "#10B981"   # id isolated / benign recon (Sub-threshold)
    ]

    y_pos = np.arange(len(labels))
    bars = ax.barh(y_pos, scores, color=colors, height=0.58, edgecolor="#1E293B", linewidth=0.8, zorder=3)

    for bar, sc in zip(bars, scores):
        xval = bar.get_width()
        ax.text(
            xval + 0.02,
            bar.get_y() + bar.get_height() / 2.0,
            f"{sc:.4f}",
            ha="left",
            va="center",
            fontsize=8,
            fontweight="bold",
            color="#0F172A"
        )

    # Threshold vertical line
    ax.axvline(0.50, color="#DC2626", linestyle="--", linewidth=1.5, zorder=4)
    ax.text(
        0.51,
        0.5,
        "Threshold = 0.50",
        color="#B91C1C",
        fontsize=8.5,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.2", facecolor="#FEE2E2", edgecolor="#DC2626", alpha=0.9),
        zorder=5
    )

    ax.set_xlim(0, 1.15)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Isolation Forest Anomaly Score", fontweight="bold", color="#1E293B")
    ax.set_title("Real GTFOBin Scores vs. 'id' Context Dynamics", fontweight="bold", color="#0F172A", pad=10)
    ax.grid(axis="x", zorder=0)

    plt.tight_layout()
    output_path = os.path.join(OUTPUT_DIR, "slide7_window_context.png")
    plt.savefig(output_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"[+] Saved: {output_path}")


def generate_synthetic_benchmark_chart():
    """Chart for Slide 10: Synthetic 3-Tier Recall & Supervised Generalization Failure."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.2, 4.3), dpi=300)
    fig.patch.set_facecolor("#FFFFFF")

    # Panel 1: Three Attack Complexity Tiers (SLR 2026 degradation)
    ax1.set_facecolor("#FAFAFA")
    tiers = ["Tier 1\n(Overt)", "Tier 2\n(Chained)", "Tier 3\n(Obfuscated)"]
    recalls = [100.0, 91.23, 90.00]
    bar_colors = ["#2563EB", "#0D9488", "#EA580C"]

    b1 = ax1.bar(tiers, recalls, color=bar_colors, width=0.52, edgecolor="#0F172A", linewidth=0.8, zorder=3)
    for b, rec in zip(b1, recalls):
        ax1.text(
            b.get_x() + b.get_width() / 2.0,
            b.get_height() + 1.8,
            f"{rec:.1f}%",
            ha="center",
            va="bottom",
            fontsize=8.5,
            fontweight="bold",
            color="#0F172A"
        )

    ax1.set_ylim(0, 115)
    ax1.set_ylabel("Detection Recall (%)", fontweight="bold", color="#1E293B")
    ax1.set_title("Three Attack Tiers\n(SLR 2026)", fontweight="bold", fontsize=10.5, color="#0F172A")
    ax1.grid(axis="y", zorder=0)

    # Panel 2: Supervised Generalization Failure (Stamp 2022) on Unseen Tiers
    ax2.set_facecolor("#FAFAFA")
    models = ["Isolation\nForest\n(Unsupervised)", "Random\nForest\n(SMOTE)", "Decision\nTree\n(SMOTE)"]
    unseen_recalls = [90.80, 48.28, 51.72]
    model_colors = ["#16A34A", "#DC2626", "#DC2626"]

    b2 = ax2.bar(models, unseen_recalls, color=model_colors, width=0.52, edgecolor="#0F172A", linewidth=0.8, zorder=3)
    for b, rec in zip(b2, unseen_recalls):
        ax2.text(
            b.get_x() + b.get_width() / 2.0,
            b.get_height() + 1.8,
            f"{rec:.1f}%",
            ha="center",
            va="bottom",
            fontsize=8.5,
            fontweight="bold",
            color="#0F172A"
        )

    ax2.set_ylim(0, 115)
    ax2.set_ylabel("Recall on Unseen Tiers (%)", fontweight="bold", color="#1E293B")
    ax2.set_title("Unseen Generalization\n(Stamp 2022)", fontweight="bold", fontsize=10.5, color="#0F172A")
    ax2.grid(axis="y", zorder=0)

    plt.tight_layout()
    output_path = os.path.join(OUTPUT_DIR, "slide10_synthetic_eval.png")
    plt.savefig(output_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"[+] Saved: {output_path}")


if __name__ == "__main__":
    generate_baseline_distribution_chart()
    generate_sliding_window_context_chart()
    generate_synthetic_benchmark_chart()
