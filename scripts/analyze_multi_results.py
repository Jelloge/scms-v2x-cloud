#!/usr/bin/env python3
"""
analyze_multi_results.py — Multi-client scalability analysis for SCMS V2X Cloud.

Reads per-client CSVs from multi_client_results/{3,5,10}_clients/ and
single-client data from data/, then generates publication-quality figures
and a summary CSV.

Output directory: multi_client_results/
"""

import os
import glob
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MULTI_DIR = os.path.join(BASE_DIR, "multi_client_results")
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = MULTI_DIR

CLIENT_COUNTS = [3, 5, 10]

# Professional color palette (ColorBrewer Set2-inspired)
COLORS = [
    "#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
    "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
]

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
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def load_client_csv(path: str) -> pd.DataFrame:
    """Load a single client CSV, filtering out rows where nothing happened."""
    df = pd.read_csv(path)
    return df


def load_multi_data() -> dict:
    """Return {num_clients: {client_id: DataFrame}}."""
    data = {}
    for n in CLIENT_COUNTS:
        folder = os.path.join(MULTI_DIR, f"{n}_clients")
        if not os.path.isdir(folder):
            print(f"  WARNING: {folder} not found, skipping")
            continue
        clients = {}
        for f in sorted(glob.glob(os.path.join(folder, "client_*.csv"))):
            cid = int(os.path.basename(f).replace("client_", "").replace(".csv", ""))
            clients[cid] = load_client_csv(f)
        data[n] = clients
        print(f"  Loaded {len(clients)} clients for {n}-client condition")
    return data


# ---------------------------------------------------------------------------
# Metric extraction
# ---------------------------------------------------------------------------

def nonzero_mean_std(series: pd.Series):
    """Return (mean, std) of non-zero values in a series."""
    vals = series[series > 0]
    if len(vals) == 0:
        return 0.0, 0.0
    return vals.mean(), vals.std()


def extract_per_client_stats(data: dict, metric: str):
    """For each client count, return lists of (mean, std) per client."""
    result = {}
    for n, clients in data.items():
        stats = []
        for cid in sorted(clients.keys()):
            m, s = nonzero_mean_std(clients[cid][metric])
            stats.append((cid, m, s))
        result[n] = stats
    return result


# ---------------------------------------------------------------------------
# Figure 1: Enrollment Latency Scaling
# ---------------------------------------------------------------------------

def fig_enrollment_latency(data: dict):
    print("  Generating fig_enrollment_latency_scaling.png")
    stats = extract_per_client_stats(data, "last_enroll_ms")
    _grouped_bar(stats, "Enrollment Latency vs. Concurrent Clients",
                 "Average Enrollment Latency (ms)",
                 os.path.join(OUTPUT_DIR, "fig_enrollment_latency_scaling.png"))


# ---------------------------------------------------------------------------
# Figure 2: Pseudonym Latency Scaling
# ---------------------------------------------------------------------------

def fig_pseudonym_latency(data: dict):
    print("  Generating fig_pseudonym_latency_scaling.png")
    stats = extract_per_client_stats(data, "last_pseudonym_ms")
    _grouped_bar(stats, "Pseudonym Batch Latency vs. Concurrent Clients",
                 "Average Pseudonym Batch Latency (ms)",
                 os.path.join(OUTPUT_DIR, "fig_pseudonym_latency_scaling.png"))


# ---------------------------------------------------------------------------
# Figure 3: BSM Signing Latency Scaling
# ---------------------------------------------------------------------------

def fig_bsm_signing(data: dict):
    print("  Generating fig_bsm_signing_scaling.png")
    stats = extract_per_client_stats(data, "last_bsm_sign_ms")
    _grouped_bar(stats, "BSM Signing Latency vs. Concurrent Clients",
                 "Average BSM Signing Latency (ms)",
                 os.path.join(OUTPUT_DIR, "fig_bsm_signing_scaling.png"),
                 deadline_line=100.0)


# ---------------------------------------------------------------------------
# Figure 4: Deadline Misses
# ---------------------------------------------------------------------------

def fig_deadline_misses(data: dict):
    print("  Generating fig_deadline_misses_scaling.png")
    fig, ax = plt.subplots(figsize=FIGSIZE)

    all_groups = []
    all_labels = []
    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        clients = data[n]
        for cid in sorted(clients.keys()):
            df = clients[cid]
            total_misses = int(df["bsm_deadline_miss"].max())
            all_groups.append((n, cid, total_misses))

    # Group bars by client count
    group_positions = []
    bar_positions = []
    bar_heights = []
    bar_colors = []
    tick_labels = []
    offset = 0
    bar_width = 0.7

    for n in CLIENT_COUNTS:
        group = [(nc, cid, v) for nc, cid, v in all_groups if nc == n]
        if not group:
            continue
        start = offset
        for i, (nc, cid, v) in enumerate(group):
            bar_positions.append(offset)
            bar_heights.append(v)
            bar_colors.append(COLORS[i % len(COLORS)])
            tick_labels.append(f"C{cid}")
            offset += 1
        group_center = (start + offset - 1) / 2.0
        group_positions.append((group_center, f"{n} Clients"))
        offset += 1.5  # gap between groups

    bars = ax.bar(bar_positions, bar_heights, width=bar_width, color=bar_colors,
                  edgecolor="white", linewidth=0.5)

    # Add value labels on bars
    for bar, h in zip(bars, bar_heights):
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h + max(bar_heights) * 0.01,
                    str(h), ha="center", va="bottom", fontsize=FONT_SIZE - 2)

    ax.set_xticks([p for p, _ in group_positions])
    ax.set_xticklabels([l for _, l in group_positions])
    ax.set_ylabel("Total BSM Deadline Misses")
    ax.set_title("BSM Deadline Misses vs. Concurrent Clients")

    plt.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_deadline_misses_scaling.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 5: Scalability Summary (dual y-axis line chart)
# ---------------------------------------------------------------------------

def fig_scalability_summary(data: dict):
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
        enroll_vals, pseudo_vals, bsm_vals = [], [], []
        for cid, df in data[n].items():
            e = df["last_enroll_ms"][df["last_enroll_ms"] > 0]
            p = df["last_pseudonym_ms"][df["last_pseudonym_ms"] > 0]
            b = df["last_bsm_sign_ms"][df["last_bsm_sign_ms"] > 0]
            if len(e) > 0:
                enroll_vals.append(e.mean())
            if len(p) > 0:
                pseudo_vals.append(p.mean())
            if len(b) > 0:
                bsm_vals.append(b.mean())

        avg_enroll.append(np.mean(enroll_vals) if enroll_vals else 0)
        avg_pseudo.append(np.mean(pseudo_vals) if pseudo_vals else 0)
        avg_bsm.append(np.mean(bsm_vals) if bsm_vals else 0)

    color_enroll = COLORS[0]
    color_pseudo = COLORS[1]
    color_bsm = COLORS[2]

    ax1.set_xlabel("Number of Concurrent Clients")
    ax1.set_ylabel("Avg Cloud Operation Latency (ms)", color="black")
    l1, = ax1.plot(xs, avg_enroll, "o-", color=color_enroll, linewidth=2,
                   markersize=8, label="Enrollment Latency")
    l2, = ax1.plot(xs, avg_pseudo, "s-", color=color_pseudo, linewidth=2,
                   markersize=8, label="Pseudonym Latency")
    ax1.tick_params(axis="y")
    ax1.set_xticks(xs)

    ax2 = ax1.twinx()
    ax2.set_ylabel("Avg BSM Signing Latency (ms)", color=color_bsm)
    l3, = ax2.plot(xs, avg_bsm, "^--", color=color_bsm, linewidth=2,
                   markersize=8, label="BSM Signing Latency")
    ax2.tick_params(axis="y", labelcolor=color_bsm)

    lines = [l1, l2, l3]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper left")

    ax1.set_title("SCMS Scalability: Cloud Latency vs. Signing Latency")
    fig.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_scalability_summary.png"), dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Summary CSV
# ---------------------------------------------------------------------------

def generate_summary_csv(data: dict):
    print("  Generating fig_multi_client_summary.csv")
    rows = []
    for n in CLIENT_COUNTS:
        if n not in data:
            continue
        for cid in sorted(data[n].keys()):
            df = data[n][cid]
            enroll_nz = df["last_enroll_ms"][df["last_enroll_ms"] > 0]
            pseudo_nz = df["last_pseudonym_ms"][df["last_pseudonym_ms"] > 0]
            bsm_nz = df["last_bsm_sign_ms"][df["last_bsm_sign_ms"] > 0]

            rows.append({
                "test_condition": f"{n}_clients",
                "num_clients": n,
                "client_id": cid,
                "avg_enroll_ms": round(enroll_nz.mean(), 3) if len(enroll_nz) else 0,
                "avg_pseudo_ms": round(pseudo_nz.mean(), 3) if len(pseudo_nz) else 0,
                "avg_bsm_sign_ms": round(bsm_nz.mean(), 3) if len(bsm_nz) else 0,
                "max_bsm_sign_ms": round(df["max_bsm_sign_ms"].max(), 3),
                "total_deadline_misses": int(df["bsm_deadline_miss"].max()),
                "avg_provisions_ok": round(df["provision_ok"].max(), 1),
            })

    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(OUTPUT_DIR, "fig_multi_client_summary.csv"), index=False)


# ---------------------------------------------------------------------------
# Shared plotting helper
# ---------------------------------------------------------------------------

def _grouped_bar(stats: dict, title: str, ylabel: str, outpath: str,
                 deadline_line: float = None):
    """Draw a grouped bar chart with per-client bars within each client-count group."""
    fig, ax = plt.subplots(figsize=FIGSIZE)

    group_positions = []
    offset = 0
    bar_width = 0.7

    for n in CLIENT_COUNTS:
        if n not in stats:
            continue
        group = stats[n]  # list of (cid, mean, std)
        start = offset
        for i, (cid, m, s) in enumerate(group):
            ax.bar(offset, m, width=bar_width, yerr=s, capsize=3,
                   color=COLORS[i % len(COLORS)], edgecolor="white", linewidth=0.5,
                   error_kw={"linewidth": 1})
            offset += 1
        group_center = (start + offset - 1) / 2.0
        group_positions.append((group_center, f"{n} Clients"))
        offset += 1.5  # gap

    if deadline_line is not None:
        ax.axhline(y=deadline_line, color="red", linestyle="--", linewidth=1.5,
                   label=f"Deadline ({deadline_line:.0f} ms)")
        ax.legend()

    ax.set_xticks([p for p, _ in group_positions])
    ax.set_xticklabels([l for _, l in group_positions])
    ax.set_ylabel(ylabel)
    ax.set_title(title)

    plt.tight_layout()
    fig.savefig(outpath, dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("SCMS V2X Multi-Client Scalability Analysis")
    print("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\nLoading multi-client data...")
    data = load_multi_data()

    if not data:
        print("ERROR: No multi-client data found. Exiting.")
        return

    print("\nGenerating figures...")
    fig_enrollment_latency(data)
    fig_pseudonym_latency(data)
    fig_bsm_signing(data)
    fig_deadline_misses(data)
    fig_scalability_summary(data)
    generate_summary_csv(data)

    print("\nDone. Output files:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        if f.startswith("fig_"):
            fpath = os.path.join(OUTPUT_DIR, f)
            size_kb = os.path.getsize(fpath) / 1024
            print(f"  {f}  ({size_kb:.0f} KB)")

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()
