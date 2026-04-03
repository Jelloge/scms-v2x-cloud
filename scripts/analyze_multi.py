"""
analyze_multi.py - Analyze multi-client concurrent test results.

Usage:
    python3 scripts/analyze_multi.py <num_clients>
    python3 scripts/analyze_multi.py 5

Reads cert_store_1/metrics.csv through cert_store_N/metrics.csv
and generates comparison charts in analysis_output/.
"""

import sys
import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_client_data(num_clients):
    """Load metrics.csv for each client, return dict of DataFrames."""
    data = {}
    for i in range(1, num_clients + 1):
        csv_path = f"cert_store_{i}/metrics.csv"
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            # convert timestamp to relative seconds from start
            if 'timestamp_ns' in df.columns and len(df) > 0:
                t0 = df['timestamp_ns'].iloc[0]
                df['elapsed_sec'] = (df['timestamp_ns'] - t0) / 1e9
            data[i] = df
            print(f"  Client {i}: {len(df)} data points loaded")
        else:
            print(f"  Client {i}: {csv_path} not found, skipping")
    return data


def plot_enrollment_latency_comparison(data, num_clients):
    """Bar chart: average enrollment latency per client."""
    fig, ax = plt.subplots(figsize=(10, 6))

    clients = sorted(data.keys())
    avgs = []
    p95s = []
    maxs = []

    for c in clients:
        df = data[c]
        enroll = df['last_enroll_ms'][df['last_enroll_ms'] > 0]
        avgs.append(enroll.mean() if len(enroll) > 0 else 0)
        p95s.append(enroll.quantile(0.95) if len(enroll) > 0 else 0)
        maxs.append(enroll.max() if len(enroll) > 0 else 0)

    x = np.arange(len(clients))
    width = 0.25

    ax.bar(x - width, avgs, width, label='Average', color='#2196F3')
    ax.bar(x, p95s, width, label='P95', color='#FF9800')
    ax.bar(x + width, maxs, width, label='Max', color='#F44336')

    ax.set_xlabel('Client ID')
    ax.set_ylabel('Enrollment Latency (ms)')
    ax.set_title(f'Enrollment Latency — {num_clients} Concurrent Clients')
    ax.set_xticks(x)
    ax.set_xticklabels([f'Client {c}' for c in clients])
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    path = os.path.join(OUTPUT_DIR, f'multi_{num_clients}c_enrollment_latency.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  -> {path}")


def plot_bsm_signing_comparison(data, num_clients):
    """Bar chart: BSM signing latency per client (should be flat)."""
    fig, ax = plt.subplots(figsize=(10, 6))

    clients = sorted(data.keys())
    avgs = []
    maxs = []

    for c in clients:
        df = data[c]
        sign = df['last_bsm_sign_ms'][df['last_bsm_sign_ms'] > 0]
        avgs.append(sign.mean() if len(sign) > 0 else 0)
        maxs.append(sign.max() if len(sign) > 0 else 0)

    x = np.arange(len(clients))
    width = 0.35

    ax.bar(x - width/2, avgs, width, label='Average', color='#4CAF50')
    ax.bar(x + width/2, maxs, width, label='Max', color='#F44336')

    ax.set_xlabel('Client ID')
    ax.set_ylabel('BSM Signing Latency (ms)')
    ax.set_title(f'BSM Signing Latency — {num_clients} Concurrent Clients')
    ax.set_xticks(x)
    ax.set_xticklabels([f'Client {c}' for c in clients])
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    path = os.path.join(OUTPUT_DIR, f'multi_{num_clients}c_bsm_signing.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  -> {path}")


def plot_deadline_misses(data, num_clients):
    """Bar chart: total deadline misses per client."""
    fig, ax = plt.subplots(figsize=(10, 6))

    clients = sorted(data.keys())
    misses = []

    for c in clients:
        df = data[c]
        if len(df) > 0:
            misses.append(df['bsm_deadline_miss'].iloc[-1])
        else:
            misses.append(0)

    ax.bar([f'Client {c}' for c in clients], misses, color='#F44336')
    ax.set_ylabel('Total Deadline Misses')
    ax.set_title(f'BSM Deadline Misses — {num_clients} Concurrent Clients')
    ax.grid(axis='y', alpha=0.3)

    path = os.path.join(OUTPUT_DIR, f'multi_{num_clients}c_deadline_misses.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  -> {path}")


def plot_enrollment_time_series(data, num_clients):
    """Time series: enrollment latency over time for all clients overlaid."""
    fig, ax = plt.subplots(figsize=(12, 6))

    colors = plt.cm.Set1(np.linspace(0, 1, max(num_clients, 3)))

    for idx, c in enumerate(sorted(data.keys())):
        df = data[c]
        enroll = df[df['last_enroll_ms'] > 0]
        if len(enroll) > 0:
            ax.plot(enroll['elapsed_sec'], enroll['last_enroll_ms'],
                    label=f'Client {c}', color=colors[idx], alpha=0.7, linewidth=1)

    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Enrollment Latency (ms)')
    ax.set_title(f'Enrollment Latency Over Time — {num_clients} Concurrent Clients')
    ax.legend()
    ax.grid(alpha=0.3)

    path = os.path.join(OUTPUT_DIR, f'multi_{num_clients}c_enrollment_timeseries.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  -> {path}")


def print_summary_table(data, num_clients):
    """Print and save summary statistics."""
    rows = []
    for c in sorted(data.keys()):
        df = data[c]
        enroll = df['last_enroll_ms'][df['last_enroll_ms'] > 0]
        sign = df['last_bsm_sign_ms'][df['last_bsm_sign_ms'] > 0]
        total_cycles = df['bsm_cycles'].iloc[-1] if len(df) > 0 else 0
        total_misses = df['bsm_deadline_miss'].iloc[-1] if len(df) > 0 else 0
        total_ok = df['provision_ok'].iloc[-1] if len(df) > 0 else 0

        rows.append({
            'client': c,
            'enroll_avg_ms': f"{enroll.mean():.1f}" if len(enroll) > 0 else "N/A",
            'enroll_p95_ms': f"{enroll.quantile(0.95):.1f}" if len(enroll) > 0 else "N/A",
            'enroll_max_ms': f"{enroll.max():.1f}" if len(enroll) > 0 else "N/A",
            'sign_avg_ms': f"{sign.mean():.3f}" if len(sign) > 0 else "N/A",
            'sign_max_ms': f"{sign.max():.3f}" if len(sign) > 0 else "N/A",
            'bsm_cycles': int(total_cycles),
            'deadline_misses': int(total_misses),
            'provisions_ok': int(total_ok),
        })

    summary_df = pd.DataFrame(rows)
    print(f"\n  Summary ({num_clients} clients):")
    print(summary_df.to_string(index=False))

    path = os.path.join(OUTPUT_DIR, f'multi_{num_clients}c_summary.csv')
    summary_df.to_csv(path, index=False)
    print(f"\n  -> {path}")


def main():
    if len(sys.argv) < 2:
        print("usage: python3 scripts/analyze_multi.py <num_clients>")
        print("e.g.:  python3 scripts/analyze_multi.py 5")
        sys.exit(1)

    num_clients = int(sys.argv[1])
    print(f"\nAnalyzing multi-client results ({num_clients} clients)...")
    print("Loading data...")

    data = load_client_data(num_clients)

    if not data:
        print("ERROR: No data found. Run tests first.")
        sys.exit(1)

    print(f"\nGenerating charts...")
    plot_enrollment_latency_comparison(data, num_clients)
    plot_bsm_signing_comparison(data, num_clients)
    plot_deadline_misses(data, num_clients)
    plot_enrollment_time_series(data, num_clients)
    print_summary_table(data, num_clients)

    print(f"\nAll output saved to {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
