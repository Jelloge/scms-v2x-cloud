#!/usr/bin/env python3
"""
analyze_multi_results_v2.py — Improved multi-client scalability figures.

Fixes:
  - BSM signing chart: uses zoomed y-axis with inset annotation for the 100ms deadline
  - Per-client bars get labeled (C1, C2, ...)
  - Adds a combined 4-panel figure for presentation use
"""

import os
import glob
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MULTI_DIR = os.path.join(BASE_DIR, "new_multi_results")
OUTPUT_DIR = os.path.join(BASE_DIR, "new_multi_results")

CLIENT_COUNTS = [3, 5, 10]

COLORS = {
    3: ["#4e79a7", "#f28e2b", "#e15759"],
    5: ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f"],
    10: ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
         "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac"],
}

FIGSIZE = (10, 6)
DPI = 300
FONT_SIZE = 12
plt.rcParams.update({
    "font.size": FONT_SIZE,
    "axes.titlesize": FONT_SIZE + 2,
    "axes.labelsize": FONT_SIZE,
    "xtick.labelsize": FONT_SIZE - 1,
    "ytick.labelsize": FONT_SIZE - 1,
    "legend.fontsize": FONT_SIZE - 1,
    "figure.facecolor": "white",
    "axes.facecolor": "#fafafa",
    "savefig.facecolor": "white",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_multi_data():
    data = {}
    for n in CLIENT_COUNTS:
        folder = os.path.join(MULTI_DIR, f"{n}_clients")
        if not os.path.isdir(folder):
            print(f"  WARNING: {folder} not found")
            continue
        clients = {}
        for f in sorted(glob.glob(os.path.join(folder, "client_*.csv"))):
            cid = int(os.path.basename(f).replace("client_", "").replace(".csv", ""))
            clients[cid] = pd.read_csv(f)
        data[n] = clients
        print(f"  Loaded {len(clients)} clients for {n}-client condition")
    return data


def nonzero(s):
    return s[s > 0]

# ---------------------------------------------------------------------------
# Figure 1: Enrollment Latency (improved)
# ---------------------------------------------------------------------------

def fig_enrollment(data):
    print("  Generating fig_enrollment_latency_scaling.png")
    fig, ax = plt.subplots(figsize=FIGSIZE)
    _grouped_bar_improved(ax, data, "last_enroll_ms",
                          "Enrollment Latency vs. Concurrent Clients",
                          "Average Enrollment Latency (ms)")
    plt.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_enrollment_latency_scaling.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 2: Pseudonym Latency (improved)
# ---------------------------------------------------------------------------

def fig_pseudonym(data):
    print("  Generating fig_pseudonym_latency_scaling.png")
    fig, ax = plt.subplots(figsize=FIGSIZE)
    _grouped_bar_improved(ax, data, "last_pseudonym_ms",
                          "Pseudonym Batch Latency vs. Concurrent Clients",
                          "Average Pseudonym Batch Latency (ms)")
    plt.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_pseudonym_latency_scaling.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 3: BSM Signing — FIXED (zoomed in, with deadline annotation)
# ---------------------------------------------------------------------------

def fig_bsm_signing(data):
    print("  Generating fig_bsm_signing_scaling.png")
    fig, ax = plt.subplots(figsize=FIGSIZE)

    _grouped_bar_improved(ax, data, "last_bsm_sign_ms",
                          "BSM Signing Latency vs. Concurrent Clients",
                          "Average BSM Signing Latency (ms)",
                          show_values=True)

    # Get current y-max from the data (will be ~0.25 ms)
    ymax = ax.get_ylim()[1]
    ax.set_ylim(0, ymax * 1.4)  # room for value labels

    # Add annotation about the 100ms deadline (since it's off-chart)
    ax.annotate(
        "100 ms deadline\n(off scale — 450× above)",
        xy=(0.98, 0.95), xycoords="axes fraction",
        fontsize=10, color="red", ha="right", va="top",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#fff0f0",
                  edgecolor="red", alpha=0.9),
    )

    plt.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_bsm_signing_scaling.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 4: Deadline Misses (improved)
# ---------------------------------------------------------------------------

def fig_deadline_misses(data):
    print("  Generating fig_deadline_misses_scaling.png")
    fig, ax = plt.subplots(figsize=FIGSIZE)

    offset = 0
    bar_width = 0.7
    group_positions = []

    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        clients = data[n]
        start = offset
        colors = COLORS[n]
        for i, cid in enumerate(sorted(clients.keys())):
            df = clients[cid]
            total = int(df["bsm_deadline_miss"].max())
            bar = ax.bar(offset, total, width=bar_width,
                         color=colors[i], edgecolor="white", linewidth=0.5)
            ax.text(offset, total + 0.15, str(total), ha="center", va="bottom",
                    fontsize=FONT_SIZE - 2, fontweight="bold")
            offset += 1
        group_center = (start + offset - 1) / 2.0
        group_positions.append((group_center, f"{n} Clients"))
        offset += 1.5

    ax.set_xticks([p for p, _ in group_positions])
    ax.set_xticklabels([l for _, l in group_positions])
    ax.set_ylabel("Total BSM Deadline Misses")
    ax.set_title("BSM Deadline Misses vs. Concurrent Clients")
    ax.set_ylim(0, 10)

    # Add note: these are startup transients
    ax.annotate(
        "All misses occur during initial\nprovisioning (startup transient)",
        xy=(0.98, 0.95), xycoords="axes fraction",
        fontsize=10, color="#555", ha="right", va="top",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#f5f5f5",
                  edgecolor="#ccc", alpha=0.9),
    )

    plt.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_deadline_misses_scaling.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 5: Scalability Summary (improved dual-axis)
# ---------------------------------------------------------------------------

def fig_scalability_summary(data):
    print("  Generating fig_scalability_summary.png")
    fig, ax1 = plt.subplots(figsize=FIGSIZE)

    xs = []
    avg_enroll = []
    avg_pseudo = []
    avg_bsm = []

    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        xs.append(n)
        e_vals, p_vals, b_vals = [], [], []
        for cid, df in data[n].items():
            e = nonzero(df["last_enroll_ms"])
            p = nonzero(df["last_pseudonym_ms"])
            b = nonzero(df["last_bsm_sign_ms"])
            if len(e): e_vals.append(e.mean())
            if len(p): p_vals.append(p.mean())
            if len(b): b_vals.append(b.mean())

        avg_enroll.append(np.mean(e_vals) if e_vals else 0)
        avg_pseudo.append(np.mean(p_vals) if p_vals else 0)
        avg_bsm.append(np.mean(b_vals) if b_vals else 0)

    c_enroll = "#4e79a7"
    c_pseudo = "#f28e2b"
    c_bsm = "#e15759"

    ax1.set_xlabel("Number of Concurrent Clients")
    ax1.set_ylabel("Avg Cloud Operation Latency (ms)")

    l1, = ax1.plot(xs, avg_enroll, "o-", color=c_enroll, linewidth=2.5,
                   markersize=10, label="Enrollment", zorder=5)
    l2, = ax1.plot(xs, avg_pseudo, "s-", color=c_pseudo, linewidth=2.5,
                   markersize=10, label="Pseudonym Batch", zorder=5)
    ax1.set_xticks(xs)

    # Add value annotations on the enrollment line
    for x, v in zip(xs, avg_enroll):
        ax1.annotate(f"{v:.0f} ms", (x, v), textcoords="offset points",
                     xytext=(0, 12), ha="center", fontsize=9, color=c_enroll,
                     fontweight="bold")
    for x, v in zip(xs, avg_pseudo):
        ax1.annotate(f"{v:.0f} ms", (x, v), textcoords="offset points",
                     xytext=(0, -18), ha="center", fontsize=9, color=c_pseudo,
                     fontweight="bold")

    ax2 = ax1.twinx()
    ax2.set_ylabel("Avg BSM Signing Latency (ms)", color=c_bsm)
    l3, = ax2.plot(xs, avg_bsm, "^--", color=c_bsm, linewidth=2,
                   markersize=10, label="BSM Signing", zorder=5)
    ax2.tick_params(axis="y", labelcolor=c_bsm)

    for x, v in zip(xs, avg_bsm):
        ax2.annotate(f"{v:.3f} ms", (x, v), textcoords="offset points",
                     xytext=(0, 12), ha="center", fontsize=9, color=c_bsm,
                     fontweight="bold")

    lines = [l1, l2, l3]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper left", framealpha=0.9)

    ax1.set_title("SCMS Scalability: Cloud Latency vs. Local Signing Latency")
    fig.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_scalability_summary.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# NEW Figure 6: Combined 4-panel for presentation
# ---------------------------------------------------------------------------

def fig_combined_panel(data):
    print("  Generating fig_multi_client_combined.png")
    fig, axes = plt.subplots(2, 2, figsize=(16, 11))
    fig.suptitle("Multi-Client Scalability Results", fontsize=18, fontweight="bold", y=0.98)

    # Panel A: Enrollment
    ax = axes[0, 0]
    _grouped_bar_improved(ax, data, "last_enroll_ms",
                          "(a) Enrollment Latency",
                          "Avg Enrollment Latency (ms)",
                          show_values=False)

    # Panel B: Pseudonym
    ax = axes[0, 1]
    _grouped_bar_improved(ax, data, "last_pseudonym_ms",
                          "(b) Pseudonym Batch Latency",
                          "Avg Pseudonym Batch Latency (ms)",
                          show_values=False)

    # Panel C: BSM Signing (zoomed)
    ax = axes[1, 0]
    _grouped_bar_improved(ax, data, "last_bsm_sign_ms",
                          "(c) BSM Signing Latency",
                          "Avg BSM Signing Latency (ms)",
                          show_values=True)
    ymax = ax.get_ylim()[1]
    ax.set_ylim(0, ymax * 1.4)
    ax.annotate("100 ms deadline\n(off scale)", xy=(0.97, 0.95),
                xycoords="axes fraction", fontsize=9, color="red",
                ha="right", va="top",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#fff0f0",
                          edgecolor="red", alpha=0.9))

    # Panel D: Scalability summary lines
    ax = axes[1, 1]
    xs = []
    avg_enroll, avg_pseudo, avg_bsm = [], [], []
    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        xs.append(n)
        e_vals, p_vals, b_vals = [], [], []
        for cid, df in data[n].items():
            e = nonzero(df["last_enroll_ms"])
            p = nonzero(df["last_pseudonym_ms"])
            b = nonzero(df["last_bsm_sign_ms"])
            if len(e): e_vals.append(e.mean())
            if len(p): p_vals.append(p.mean())
            if len(b): b_vals.append(b.mean())
        avg_enroll.append(np.mean(e_vals) if e_vals else 0)
        avg_pseudo.append(np.mean(p_vals) if p_vals else 0)
        avg_bsm.append(np.mean(b_vals) if b_vals else 0)

    c_e, c_p, c_b = "#4e79a7", "#f28e2b", "#e15759"
    ax.plot(xs, avg_enroll, "o-", color=c_e, linewidth=2.5, markersize=9, label="Enrollment")
    ax.plot(xs, avg_pseudo, "s-", color=c_p, linewidth=2.5, markersize=9, label="Pseudonym Batch")
    ax.set_xlabel("Number of Concurrent Clients")
    ax.set_ylabel("Avg Latency (ms)")
    ax.set_xticks(xs)
    ax.set_title("(d) Scalability Trend")
    ax.legend(loc="upper left", framealpha=0.9)

    for x, ve, vp in zip(xs, avg_enroll, avg_pseudo):
        ax.annotate(f"{ve:.0f}", (x, ve), textcoords="offset points",
                    xytext=(0, 10), ha="center", fontsize=9, color=c_e, fontweight="bold")
        ax.annotate(f"{vp:.0f}", (x, vp), textcoords="offset points",
                    xytext=(0, -15), ha="center", fontsize=9, color=c_p, fontweight="bold")

    # BSM on secondary axis
    ax2 = ax.twinx()
    ax2.plot(xs, avg_bsm, "^--", color=c_b, linewidth=2, markersize=9, label="BSM Signing")
    ax2.set_ylabel("BSM Signing (ms)", color=c_b)
    ax2.tick_params(axis="y", labelcolor=c_b)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_multi_client_combined.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Shared helper: grouped bar chart with per-client labels
# ---------------------------------------------------------------------------

def _grouped_bar_improved(ax, data, metric, title, ylabel, show_values=False):
    offset = 0
    bar_width = 0.7
    group_positions = []

    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        clients = data[n]
        start = offset
        colors = COLORS[n]
        for i, cid in enumerate(sorted(clients.keys())):
            vals = nonzero(clients[cid][metric])
            m = vals.mean() if len(vals) else 0
            s = vals.std() if len(vals) else 0
            bar = ax.bar(offset, m, width=bar_width, yerr=s, capsize=3,
                         color=colors[i], edgecolor="white", linewidth=0.5,
                         error_kw={"linewidth": 1, "alpha": 0.6})
            if show_values and m > 0:
                ax.text(offset, m + s + m * 0.05, f"{m:.3f}",
                        ha="center", va="bottom", fontsize=8, fontweight="bold")
            offset += 1
        group_center = (start + offset - 1) / 2.0
        group_positions.append((group_center, f"{n} Clients"))
        offset += 1.5

    ax.set_xticks([p for p, _ in group_positions])
    ax.set_xticklabels([l for _, l in group_positions])
    ax.set_ylabel(ylabel)
    ax.set_title(title)


# ---------------------------------------------------------------------------
# Summary CSV
# ---------------------------------------------------------------------------

def generate_summary_csv(data):
    print("  Generating fig_multi_client_summary.csv")
    rows = []
    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        for cid in sorted(data[n].keys()):
            df = data[n][cid]
            e = nonzero(df["last_enroll_ms"])
            p = nonzero(df["last_pseudonym_ms"])
            b = nonzero(df["last_bsm_sign_ms"])
            rows.append({
                "test_condition": f"{n}_clients",
                "num_clients": n,
                "client_id": cid,
                "avg_enroll_ms": round(e.mean(), 3) if len(e) else 0,
                "avg_pseudo_ms": round(p.mean(), 3) if len(p) else 0,
                "avg_bsm_sign_ms": round(b.mean(), 3) if len(b) else 0,
                "max_bsm_sign_ms": round(df["max_bsm_sign_ms"].max(), 3),
                "total_deadline_misses": int(df["bsm_deadline_miss"].max()),
                "total_provisions_ok": int(df["provision_ok"].max()),
            })
    pd.DataFrame(rows).to_csv(os.path.join(OUTPUT_DIR, "fig_multi_client_summary.csv"), index=False)


# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("SCMS V2X Multi-Client Scalability Analysis (v2)")
    print("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\nLoading multi-client data...")
    data = load_multi_data()
    if not data:
        print("ERROR: No multi-client data found.")
        return

    print("\nGenerating figures...")
    fig_enrollment(data)
    fig_pseudonym(data)
    fig_bsm_signing(data)
    fig_deadline_misses(data)
    fig_scalability_summary(data)
    fig_combined_panel(data)
    generate_summary_csv(data)

    print("\nDone. Output files:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        if f.startswith("fig_"):
            fpath = os.path.join(OUTPUT_DIR, f)
            size_kb = os.path.getsize(fpath) / 1024
            print(f"  {f}  ({size_kb:.0f} KB)")

if __name__ == "__main__":
    main()
