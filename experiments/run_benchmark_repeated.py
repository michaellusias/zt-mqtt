"""
Repeated-trials benchmark: runs the full plain/TLS/ZT comparison as N
independent trials (fresh broker + fresh enforcement-monitor proxy
process per trial, not just repeated calls against warm state) and
aggregates to mean +/- 95% confidence interval.

Why independent trials, not just "loop the measurement 30x in one
session": the trust-scoring layer carries state across a client's
connected lifetime by design (see trust_scorer.py) -- reusing one warm
proxy process across repetitions would let earlier repetitions leak into
later ones (e.g. rate-window counters not fully reset), which would bias
the aggregate. A fresh process per trial removes that confound at the
cost of runtime.

95% CI uses Student's t-distribution (not a normal-distribution
approximation), which is the appropriate choice for the small trial
counts (N=10-20) typical of a one-semester project. Critical values are
looked up from a standard t-table -- do not swap in 1.96 (that's the
z-value, valid only as N -> large).
"""
import csv
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subprocess
from experiments.run_benchmark import (
    wait_for_port, run_plain, run_tls, run_zt, RESULTS_DIR,
)
from experiments.metrics import ResourceSampler

N_TRIALS = 10

# Student's t critical values for a two-tailed 95% CI, indexed by degrees
# of freedom (df = N_TRIALS - 1). Falls back to the N->inf (z) value for
# df beyond this table's range.
T_TABLE_95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    25: 2.060, 30: 2.042,
}


def t_critical_95(df: int) -> float:
    if df in T_TABLE_95:
        return T_TABLE_95[df]
    closest = min(T_TABLE_95.keys(), key=lambda k: abs(k - df)) if df < 30 else 30
    return T_TABLE_95.get(closest, 1.96)


def mean_ci95(values):
    n = len(values)
    if n < 2:
        return statistics.mean(values), float("nan"), float("nan")
    m = statistics.mean(values)
    sd = statistics.stdev(values)
    t = t_critical_95(n - 1)
    margin = t * sd / (n ** 0.5)
    return m, m - margin, m + margin


def run_one_trial(scheme_name, run_fn, broker_pid_holder, proxy_pid_holder):
    broker = subprocess.Popen([sys.executable, "broker/run_broker.py"])
    broker_pid_holder["pid"] = broker.pid
    wait_for_port("127.0.0.1", 1885)
    wait_for_port("127.0.0.1", 8883)
    time.sleep(0.4)

    proxy = subprocess.Popen([sys.executable, "-m", "enforcement_monitor.proxy"])
    proxy_pid_holder["pid"] = proxy.pid
    wait_for_port("127.0.0.1", 1884)
    time.sleep(0.4)

    sample_pid = proxy.pid if scheme_name == "zt" else broker.pid
    sampler = ResourceSampler(sample_pid)
    sampler.start()
    try:
        connect_latencies, e2e_latencies = run_fn()
    finally:
        sampler.stop()
        proxy.terminate()
        broker.terminate()
        proxy.wait(timeout=5)
        broker.wait(timeout=5)

    res = sampler.summary()
    return {
        "connect_latency_mean_ms": statistics.mean(connect_latencies) * 1000,
        "e2e_latency_mean_ms": statistics.mean(e2e_latencies) * 1000 if e2e_latencies else float("nan"),
        "cpu_mean_pct": res["cpu_mean_pct"],
        "mem_mean_mb": res["mem_mean_mb"],
    }


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    schemes = [("plain", run_plain), ("tls", run_tls), ("zt", run_zt)]

    raw_rows = []
    for scheme_name, run_fn in schemes:
        print(f"\n=== {scheme_name}: running {N_TRIALS} independent trials ===")
        for trial in range(N_TRIALS):
            result = run_one_trial(scheme_name, run_fn, {}, {})
            result["scheme"] = scheme_name
            result["trial"] = trial
            raw_rows.append(result)
            print(f"  trial {trial+1}/{N_TRIALS}: "
                  f"connect={result['connect_latency_mean_ms']:.2f}ms "
                  f"e2e={result['e2e_latency_mean_ms']:.2f}ms "
                  f"cpu={result['cpu_mean_pct']:.2f}%")

    raw_path = os.path.join(RESULTS_DIR, "benchmark_trials_raw.csv")
    with open(raw_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scheme", "trial", "connect_latency_mean_ms",
                                           "e2e_latency_mean_ms", "cpu_mean_pct", "mem_mean_mb"])
        w.writeheader()
        w.writerows(raw_rows)
    print(f"\nWrote {raw_path}")

    summary_rows = []
    for scheme_name, _ in schemes:
        trials = [r for r in raw_rows if r["scheme"] == scheme_name]
        row = {"scheme": scheme_name, "n_trials": len(trials)}
        for metric in ["connect_latency_mean_ms", "e2e_latency_mean_ms", "cpu_mean_pct", "mem_mean_mb"]:
            vals = [t[metric] for t in trials]
            m, lo, hi = mean_ci95(vals)
            row[f"{metric}_mean"] = m
            row[f"{metric}_ci95_lo"] = lo
            row[f"{metric}_ci95_hi"] = hi
        summary_rows.append(row)

    summary_path = os.path.join(RESULTS_DIR, "benchmark_summary_ci95.csv")
    with open(summary_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        w.writeheader()
        w.writerows(summary_rows)
    print(f"Wrote {summary_path}")

    print("\n=== summary (mean [95% CI]) ===")
    for row in summary_rows:
        print(f"{row['scheme']}: "
              f"connect={row['connect_latency_mean_ms_mean']:.2f}ms "
              f"[{row['connect_latency_mean_ms_ci95_lo']:.2f}, {row['connect_latency_mean_ms_ci95_hi']:.2f}]  "
              f"e2e={row['e2e_latency_mean_ms_mean']:.2f}ms "
              f"[{row['e2e_latency_mean_ms_ci95_lo']:.2f}, {row['e2e_latency_mean_ms_ci95_hi']:.2f}]")

    try:
        plot_with_error_bars(summary_rows)
    except Exception as e:
        print(f"(plotting skipped: {e})")


def plot_with_error_bars(rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    schemes = [r["scheme"] for r in rows]
    colors = ["#6b7280", "#2563eb", "#16a34a"]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))

    for ax, metric, title in [
        (axes[0], "connect_latency_mean_ms", "Auth/Connect latency (ms)"),
        (axes[1], "e2e_latency_mean_ms", "End-to-end pub->sub latency (ms)"),
        (axes[2], "cpu_mean_pct", "CPU usage of security layer (mean %)"),
    ]:
        means = [r[f"{metric}_mean"] for r in rows]
        errs = [r[f"{metric}_mean"] - r[f"{metric}_ci95_lo"] for r in rows]
        ax.bar(schemes, means, yerr=errs, capsize=6, color=colors)
        ax.set_title(title)

    fig.suptitle(f"Zero-Trust MQTT Enforcement Monitor — {N_TRIALS} independent trials, mean ± 95% CI")
    fig.tight_layout()
    out_path = os.path.join(RESULTS_DIR, "benchmark_plot_ci95.png")
    fig.savefig(out_path, dpi=140)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
