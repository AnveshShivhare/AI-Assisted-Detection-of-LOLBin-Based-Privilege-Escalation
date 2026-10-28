#!/usr/bin/env python3
"""
generate_simplified_charts.py
=============================
Generates clean, simple, high-resolution charts for the simplified 7-slide deck.
Focuses on clear academic presentation without unnecessary math clutter.
"""

import os
import matplotlib.pyplot as plt

OUTPUT_DIR = "presentation/assets_simplified"
os.makedirs(OUTPUT_DIR, exist_ok=True)

plt.rcParams.update({
    "font.sans-serif": "DejaVu Sans",
    "font.family": "sans-serif",
    "font.size": 10,
    "axes.edgecolor": "#CBD5E1",
    "axes.linewidth": 1.0,
    "grid.color": "#F1F5F9",
    "grid.linestyle": "--"
})

def create_slide5_chart():
    fig, ax = plt.subplots(figsize=(5.8, 4.1), dpi=300)
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FAFAFA")

    ranges = ["0.0 - 0.2", "0.2 - 0.4", "0.4 - 0.5", "0.5 - 0.6", "0.6 - 0.8", "0.8 - 1.0"]
    percentages = [87.4, 7.0, 1.0, 0.7, 1.4, 2.6]
    counts = [6682, 532, 78, 52, 106, 199]
    colors = ["#1E3A8A", "#2563EB", "#60A5FA", "#F59E0B", "#EF4444", "#DC2626"]

    bars = ax.bar(ranges, percentages, color=colors, width=0.55, edgecolor="#0F172A", linewidth=0.8, zorder=3)
    for b, p, c in zip(bars, percentages, counts):
        ax.text(b.get_x() + b.get_width()/2., b.get_height() + 1.5, f"{p:.1f}%\n({c})",
                ha="center", va="bottom", fontsize=8, fontweight="bold", color="#1E293B")

    ax.axvline(2.5, color="#DC2626", linestyle="--", linewidth=1.5, zorder=4)
    ax.text(2.55, 68, "Alarm Threshold (0.50)\n95.4% Normal Activity Ignored",
            color="#B91C1C", fontsize=8.5, fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#FEE2E2", edgecolor="#DC2626", alpha=0.95))

    ax.set_ylim(0, 104)
    ax.set_ylabel("Share of Baseline Activity (%)", fontweight="bold", color="#1E293B", fontsize=10)
    ax.set_xlabel("Anomaly Score (0.0 = Normal, 1.0 = Anomaly)", fontweight="bold", color="#1E293B", fontsize=9.5)
    ax.set_title("Real Ubuntu Activity Score Distribution (N=7,649)", fontweight="bold", color="#0F172A", fontsize=11, pad=10)
    ax.grid(axis="y", zorder=0)
    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "slide5_baseline_simple.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[+] Saved: {out_path}")

def create_slide6_chart():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.2, 4.1), dpi=300)
    fig.patch.set_facecolor("#FFFFFF")

    # Panel 1: Three Attack Tiers
    ax1.set_facecolor("#FAFAFA")
    tiers = ["Tier 1\nOvert", "Tier 2\nChained", "Tier 3\nStealthy"]
    recalls = [100.0, 91.2, 90.0]
    c_list = ["#2563EB", "#0D9488", "#EA580C"]
    b1 = ax1.bar(tiers, recalls, color=c_list, width=0.5, edgecolor="#0F172A", linewidth=0.8, zorder=3)
    for b, r in zip(b1, recalls):
        ax1.text(b.get_x() + b.get_width()/2., b.get_height() + 1.5, f"{r:.1f}%",
                 ha="center", va="bottom", fontsize=8.5, fontweight="bold", color="#0F172A")
    ax1.set_ylim(0, 115)
    ax1.set_ylabel("Command-Level Catch Rate (%)", fontweight="bold", color="#1E293B", fontsize=9)
    ax1.set_title("Attack Complexity Tiers", fontweight="bold", fontsize=10, color="#0F172A")
    ax1.grid(axis="y", zorder=0)

    # Panel 2: Chain-Level Interception
    ax2.set_facecolor("#FAFAFA")
    categories = ["Single\nCommands", "3-Command\nWindow"]
    chain_rates = [51.0, 100.0]  # Isolated command baseline was 51.0% recall, 3-command window caught 100% of chains
    c_list2 = ["#94A3B8", "#16A34A"]
    b2 = ax2.bar(categories, chain_rates, color=c_list2, width=0.5, edgecolor="#0F172A", linewidth=0.8, zorder=3)
    for b, r in zip(b2, chain_rates):
        ax2.text(b.get_x() + b.get_width()/2., b.get_height() + 1.5, f"{r:.1f}%",
                 ha="center", va="bottom", fontsize=8.5, fontweight="bold", color="#0F172A")
    ax2.text(1, 40, "100% Attack\nChains Stopped!\n(60 of 60)", ha="center", va="center",
             color="#166534", fontsize=8.5, fontweight="bold",
             bbox=dict(boxstyle="round,pad=0.25", facecolor="#DCFCE7", edgecolor="#16A34A", alpha=0.95))
    ax2.set_ylim(0, 115)
    ax2.set_ylabel("Attack Interception Rate (%)", fontweight="bold", color="#1E293B", fontsize=9)
    ax2.set_title("Attack Chain Interception", fontweight="bold", fontsize=10, color="#0F172A")
    ax2.grid(axis="y", zorder=0)

    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "slide6_benchmark_simple.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[+] Saved: {out_path}")

if __name__ == "__main__":
    create_slide5_chart()
    create_slide6_chart()
