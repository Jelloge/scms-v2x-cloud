import os
import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


# Paths
SRC_DIR = os.path.dirname(os.path.abspath(__file__))   # main/src
BASE_DIR = os.path.dirname(SRC_DIR)                    # main
DATA_DIR = os.path.join(BASE_DIR, "data")              # main/data
OUTPUT_DIR = os.path.join(BASE_DIR, "analysis_output") # main/analysis_output

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


# File names
latency_files = {
    "baseline": os.path.join(DATA_DIR, "baseline.csv"),
    "60s": os.path.join(DATA_DIR, "rate_60s.csv"),
    "12s": os.path.join(DATA_DIR, "rate_12s.csv"),
    "6s": os.path.join(DATA_DIR, "rate_6s.csv"),
    "3s": os.path.join(DATA_DIR, "rate_3s.csv"),
}

resource_files = {
    "baseline": os.path.join(DATA_DIR, "resource_baseline.csv"),
    "60s": os.path.join(DATA_DIR, "resource_rate_60s.csv"),
    "12s": os.path.join(DATA_DIR, "resource_rate_12s.csv"),
    "6s": os.path.join(DATA_DIR, "resource_rate_6s.csv"),
    "3s": os.path.join(DATA_DIR, "resource_rate_3s.csv"),
}

order = ["baseline", "60s", "12s", "6s", "3s"]


# parse resource file
def parse_resource_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    parts = re.split(r"--- t=(\d+)s ---", text)
    rows = []

    i = 1
    while i < len(parts):
        t_value = int(parts[i])
        block = parts[i + 1]

        def find_number(pattern):
            m = re.search(pattern, block)
            if m:
                return int(m.group(1))
            return np.nan

        vmrss = find_number(r"VmRSS:\s+(\d+)\s+kB")
        vmsize = find_number(r"VmSize:\s+(\d+)\s+kB")
        threads = find_number(r"Threads:\s+(\d+)")
        voluntary = find_number(r"voluntary_ctxt_switches:\s+(\d+)")
        nonvoluntary = find_number(r"nonvoluntary_ctxt_switches:\s+(\d+)")

        rows.append({
            "t_s": t_value,
            "VmRSS_kB": vmrss,
            "VmSize_kB": vmsize,
            "Threads": threads,
            "voluntary_ctxt_switches": voluntary,
            "nonvoluntary_ctxt_switches": nonvoluntary,
        })

        i += 2

    df = pd.DataFrame(rows)
    return df


# Read latency data
latency_summary_rows = []
raw_latency = {}

for condition in order:
    file_path = latency_files[condition]
    df = pd.read_csv(file_path)
    raw_latency[condition] = df

    duration_s = (df["timestamp_ns"].iloc[-1] - df["timestamp_ns"].iloc[0]) / 1e9
    cycles_final = df["bsm_cycles"].iloc[-1]
    deadline_misses_final = df["bsm_deadline_miss"].iloc[-1]

    if cycles_final == 0:
        deadline_miss_rate = 0
    else:
        deadline_miss_rate = deadline_misses_final / cycles_final * 100

    row = {
        "condition": condition,
        "duration_s": duration_s,
        "cycles_final": cycles_final,
        "deadline_misses_final": deadline_misses_final,
        "deadline_miss_rate_pct": deadline_miss_rate,
        "provision_ok_final": df["provision_ok"].iloc[-1],
        "provision_fail_final": df["provision_fail"].iloc[-1],
    }

    # BSM signing
    bsm_vals = df["last_bsm_sign_ms"]
    bsm_vals = bsm_vals[bsm_vals > 0]
    if len(bsm_vals) > 0:
        row["bsm_sign_mean_ms"] = bsm_vals.mean()
        row["bsm_sign_p95_ms"] = np.percentile(bsm_vals, 95)
        row["bsm_sign_max_ms"] = bsm_vals.max()
    else:
        row["bsm_sign_mean_ms"] = 0
        row["bsm_sign_p95_ms"] = 0
        row["bsm_sign_max_ms"] = 0

    # Enrollment
    enroll_vals = df["last_enroll_ms"]
    enroll_vals = enroll_vals[enroll_vals > 0]
    if len(enroll_vals) > 0:
        row["enroll_mean_ms"] = enroll_vals.mean()
        row["enroll_p95_ms"] = np.percentile(enroll_vals, 95)
        row["enroll_max_ms"] = enroll_vals.max()
    else:
        row["enroll_mean_ms"] = 0
        row["enroll_p95_ms"] = 0
        row["enroll_max_ms"] = 0

    # Pseudonym
    pseudo_vals = df["last_pseudonym_ms"]
    pseudo_vals = pseudo_vals[pseudo_vals > 0]
    if len(pseudo_vals) > 0:
        row["pseudonym_mean_ms"] = pseudo_vals.mean()
        row["pseudonym_p95_ms"] = np.percentile(pseudo_vals, 95)
        row["pseudonym_max_ms"] = pseudo_vals.max()
    else:
        row["pseudonym_mean_ms"] = 0
        row["pseudonym_p95_ms"] = 0
        row["pseudonym_max_ms"] = 0

    # crl check
    crl_vals = df["last_crl_check_ms"]
    crl_vals = crl_vals[crl_vals > 0]
    if len(crl_vals) > 0:
        row["crl_check_mean_ms"] = crl_vals.mean()
        row["crl_check_p95_ms"] = np.percentile(crl_vals, 95)
        row["crl_check_max_ms"] = crl_vals.max()
    else:
        row["crl_check_mean_ms"] = 0
        row["crl_check_p95_ms"] = 0
        row["crl_check_max_ms"] = 0

    # revoke request
    revoke_vals = df["revoke_request_ms"]
    revoke_vals = revoke_vals[revoke_vals > 0]
    if len(revoke_vals) > 0:
        row["revoke_request_mean_ms"] = revoke_vals.mean()
        row["revoke_request_p95_ms"] = np.percentile(revoke_vals, 95)
        row["revoke_request_max_ms"] = revoke_vals.max()
    else:
        row["revoke_request_mean_ms"] = 0
        row["revoke_request_p95_ms"] = 0
        row["revoke_request_max_ms"] = 0

    latency_summary_rows.append(row)

latency_summary = pd.DataFrame(latency_summary_rows)
latency_summary.to_csv(os.path.join(OUTPUT_DIR, "latency_summary.csv"), index=False)


# Read resource data
resource_summary_rows = []
raw_resource = {}

for condition in order:
    file_path = resource_files[condition]
    df = parse_resource_file(file_path)
    raw_resource[condition] = df

    row = {
        "condition": condition,
        "duration_s": df["t_s"].max(),
        "VmRSS_mean_kB": df["VmRSS_kB"].mean(),
        "VmRSS_max_kB": df["VmRSS_kB"].max(),
        "VmSize_mean_kB": df["VmSize_kB"].mean(),
        "Threads_mean": df["Threads"].mean(),
        "Threads_max": df["Threads"].max(),
        "voluntary_ctxt_switches_final": df["voluntary_ctxt_switches"].iloc[-1],
        "nonvoluntary_ctxt_switches_final": df["nonvoluntary_ctxt_switches"].iloc[-1],
    }

    resource_summary_rows.append(row)

resource_summary = pd.DataFrame(resource_summary_rows)
resource_summary.to_csv(os.path.join(OUTPUT_DIR, "resource_summary.csv"), index=False)


# Figure 1: BSM signing latency bar chart
bsm_means = []

for condition in order:
    vals = raw_latency[condition]["last_bsm_sign_ms"]
    vals = vals[vals > 0]

    if len(vals) > 0:
        mean_val = vals.mean()
    else:
        mean_val = 0

    bsm_means.append(mean_val)

plt.figure(figsize=(8, 5))
plt.bar(order, bsm_means)
plt.xlabel("Provisioning interval")
plt.ylabel("BSM signing latency (ms)")
plt.title("Mean BSM signing latency")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "fig1_bsm_sign_bar.png"), dpi=200)
plt.close()


# Figure 2: Provisioning latency (without baseline)
plot_conditions = ["60s", "12s", "6s", "3s"]

plot_df = latency_summary[latency_summary["condition"].isin(plot_conditions)].copy()

x = np.arange(len(plot_conditions))
w = 0.35

plt.figure(figsize=(9, 5))
plt.bar(x - w/2, plot_df["enroll_mean_ms"], width=w, label="Enrollment mean")
plt.bar(x + w/2, plot_df["pseudonym_mean_ms"], width=w, label="Pseudonym mean")

plt.xticks(x, plot_conditions)
plt.xlabel("Provisioning interval")
plt.ylabel("Latency (ms)")
plt.title("Provisioning latency by condition")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "fig2_provisioning_grouped_bar.png"), dpi=200)
plt.close()



# Figure 3: Deadline miss rate
plt.figure(figsize=(8, 5))
plt.bar(order, latency_summary["deadline_miss_rate_pct"])
plt.xlabel("Provisioning interval")
plt.ylabel("Deadline miss rate (%)")
plt.title("BSM deadline miss rate")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "fig3_deadline_miss_bar.png"), dpi=200)
plt.close()

# Figure 3: Deadline miss rate
plt.figure(figsize = (8, 5))
plt.bar(order, Latency_summary["Deadline_Miss_Rate_PCT"])
plt.xLabel("Provisioning interval")
plt.ylabel("Deadline miss rate (%)")
plt.title("BSM deadline msis rate")
plt.tight_layout()

# Figure 4: Time series for 3s
df_3s = raw_latency["3s"].copy()
time_s = (df_3s["timestamp_ns"] - df_3s["timestamp_ns"].iloc[0]) / 1e9

plt.figure(figsize=(9, 5))
plt.plot(time_s, df_3s["last_enroll_ms"], label="Enroll")
plt.plot(time_s, df_3s["last_pseudonym_ms"], label="Pseudonym")
plt.plot(time_s, df_3s["last_bsm_sign_ms"], label="BSM sign")
plt.xlabel("Time since start (s)")
plt.ylabel("Latency (ms)")
plt.title("Latency over time (3s provisioning interval)")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "fig4_time_series_3s.png"), dpi=200)
plt.close()


# Figure 5: Resource summary
plt.figure(figsize=(8, 5))
plt.bar(order, resource_summary["VmRSS_mean_kB"] / 1024)
plt.xlabel("Provisioning interval")
plt.ylabel("Mean VmRSS (MB)")
plt.title("Mean memory usage")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "fig5_resource_summary.png"), dpi=200)
plt.close()


# Figure 6: Chen Action 2 vs our enrollment latency
chen_action2_ms = 322

x = np.arange(len(order))
chen_values = [chen_action2_ms] * len(order)
our_values = latency_summary["enroll_mean_ms"]

plt.figure(figsize=(9, 5))
plt.bar(x - w/2, chen_values, width=w, label="Chen Action 2 (local baseline)")
plt.bar(x + w/2, our_values, width=w, label="Our enrollment mean (cloud)")
plt.xticks(x, order)
plt.xlabel("Provisioning interval")
plt.ylabel("Latency (ms)")
plt.title("Enrollment latency vs Chen Action 2 baseline")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "fig6_chen_compare.png"), dpi=200)
plt.close()


print("Done. Generated summaries and figures.")