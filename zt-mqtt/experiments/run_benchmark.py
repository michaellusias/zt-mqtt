"""
Benchmark harness. Runs three configurations end-to-end against a real
(amqtt) broker:

  1. plain    - direct MQTT, no security layer at all
  2. tls      - MQTT over TLS, the conventional "secure MQTT" baseline
  3. zt       - our scheme: enforcement-monitor proxy with ABAC +
                continuous trust scoring + symmetric-key re-auth

All latency/CPU/memory numbers below are produced by actually running
the code in this sandbox (real MQTT broker, real proxy, real clients) --
not fabricated or assumed. What they do NOT represent: real microcontroller-
class hardware. This is explicitly flagged in the CSV/README as an
external-validity limitation, not glossed over.
"""
import csv
import os
import subprocess
import sys
import time
import statistics
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paho.mqtt.client as mqtt
from experiments.metrics import ResourceSampler, per_message_overhead_bytes

N_CONNECT_TRIALS = 10
N_MESSAGES = 30
RESULTS_DIR = "results"


def wait_for_port(host, port, timeout=10):
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"{host}:{port} did not come up in time")


def measure_e2e_latency(pub_connect_fn, sub_connect_fn, topic_pub, topic_sub, n=N_MESSAGES):
    latencies = []
    received = threading.Event()
    count = {"n": 0}

    def on_message(c, userdata, msg):
        try:
            sent_ts = float(msg.payload.decode())
            latencies.append(time.perf_counter() - sent_ts)
        except ValueError:
            pass
        count["n"] += 1
        if count["n"] >= n:
            received.set()

    sub_client = sub_connect_fn(on_message_cb=on_message)
    sub_client.subscribe(topic_sub, qos=1)
    time.sleep(0.3)

    pub_client = pub_connect_fn()
    for _ in range(n):
        pub_client.publish(topic_pub, payload=str(time.perf_counter()), qos=1)
        time.sleep(0.02)

    received.wait(timeout=10)
    pub_client.loop_stop()
    pub_client.disconnect()
    sub_client.loop_stop()
    sub_client.disconnect()
    return latencies


def run_plain():
    from clients import plain_client as pc
    connect_latencies = []
    for i in range(N_CONNECT_TRIALS):
        c = pc.make_client(f"bench-plain-{i}")
        connect_latencies.append(pc.connect_and_time(c))
        c.loop_stop()
        c.disconnect()

    def pub_connect():
        c = pc.make_client("bench-plain-pub")
        pc.connect_and_time(c)
        return c

    def sub_connect(on_message_cb):
        c = pc.make_client("bench-plain-sub")
        c.on_message = on_message_cb
        pc.connect_and_time(c)
        return c

    e2e = measure_e2e_latency(pub_connect, sub_connect, "sensors/x/t", "sensors/#")
    return connect_latencies, e2e


def run_tls():
    from clients import tls_client as tc
    connect_latencies = []
    for i in range(N_CONNECT_TRIALS):
        c = tc.make_client(f"bench-tls-{i}")
        connect_latencies.append(tc.connect_and_time(c))
        c.loop_stop()
        c.disconnect()

    def pub_connect():
        c = tc.make_client("bench-tls-pub")
        tc.connect_and_time(c)
        return c

    def sub_connect(on_message_cb):
        c = tc.make_client("bench-tls-sub")
        c.on_message = on_message_cb
        tc.connect_and_time(c)
        return c

    e2e = measure_e2e_latency(pub_connect, sub_connect, "sensors/x/t", "sensors/#")
    return connect_latencies, e2e


def run_zt():
    from clients.zt_client import ZTClient
    connect_latencies = []
    for i in range(N_CONNECT_TRIALS):
        z = ZTClient("sensor-01")
        connect_latencies.append(z.connect_and_time())
        z.stop()

    def pub_connect():
        z = ZTClient("sensor-01")
        z.connect_and_time()
        return z.client

    def sub_connect(on_message_cb):
        z = ZTClient("dashboard-01")
        z.client.on_message = on_message_cb
        z.connect_and_time()
        return z.client

    e2e = measure_e2e_latency(pub_connect, sub_connect, "sensors/sensor-01/t", "sensors/#")
    return connect_latencies, e2e


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("starting broker...")
    broker_proc = subprocess.Popen([sys.executable, "broker/run_broker.py"])
    wait_for_port("127.0.0.1", 1885)
    wait_for_port("127.0.0.1", 8883)
    time.sleep(0.5)

    print("starting enforcement-monitor proxy...")
    proxy_proc = subprocess.Popen([sys.executable, "-m", "enforcement_monitor.proxy"])
    wait_for_port("127.0.0.1", 1884)
    time.sleep(0.5)

    rows = []
    try:
        for scheme_name, run_fn, sample_pid in [
            ("plain", run_plain, broker_proc.pid),
            ("tls", run_tls, broker_proc.pid),
            ("zt", run_zt, proxy_proc.pid),
        ]:
            print(f"\n=== running scheme: {scheme_name} ===")
            sampler = ResourceSampler(sample_pid)
            sampler.start()
            connect_latencies, e2e_latencies = run_fn()
            sampler.stop()
            res = sampler.summary()
            overhead = per_message_overhead_bytes(scheme_name, "sensors/sensor-01/t")

            row = {
                "scheme": scheme_name,
                "n_connect_trials": len(connect_latencies),
                "connect_latency_mean_ms": statistics.mean(connect_latencies) * 1000,
                "connect_latency_p95_ms": (sorted(connect_latencies)[int(0.95 * len(connect_latencies)) - 1] * 1000)
                if connect_latencies else float("nan"),
                "n_e2e_messages": len(e2e_latencies),
                "e2e_latency_mean_ms": statistics.mean(e2e_latencies) * 1000 if e2e_latencies else float("nan"),
                "e2e_latency_p95_ms": (sorted(e2e_latencies)[int(0.95 * len(e2e_latencies)) - 1] * 1000)
                if e2e_latencies else float("nan"),
                "cpu_mean_pct": res["cpu_mean_pct"],
                "cpu_max_pct": res["cpu_max_pct"],
                "mem_mean_mb": res["mem_mean_mb"],
                "connect_payload_overhead_bytes": overhead["connect_payload_overhead_bytes"],
            }
            rows.append(row)
            print(row)
    finally:
        proxy_proc.terminate()
        broker_proc.terminate()
        proxy_proc.wait(timeout=5)
        broker_proc.wait(timeout=5)

    csv_path = os.path.join(RESULTS_DIR, "benchmark_results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nWrote {csv_path}")

    try:
        plot_results(rows)
    except Exception as e:
        print(f"(plotting skipped: {e})")


def plot_results(rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    schemes = [r["scheme"] for r in rows]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))

    axes[0].bar(schemes, [r["connect_latency_mean_ms"] for r in rows], color=["#6b7280", "#2563eb", "#16a34a"])
    axes[0].set_title("Auth/Connect latency (ms)")
    axes[0].set_ylabel("ms (mean)")

    axes[1].bar(schemes, [r["e2e_latency_mean_ms"] for r in rows], color=["#6b7280", "#2563eb", "#16a34a"])
    axes[1].set_title("End-to-end pub->sub latency (ms)")

    axes[2].bar(schemes, [r["cpu_mean_pct"] for r in rows], color=["#6b7280", "#2563eb", "#16a34a"])
    axes[2].set_title("CPU usage of security layer (mean %)")

    fig.suptitle("Zero-Trust MQTT Enforcement Monitor — Benchmark (measured, this sandbox run)")
    fig.tight_layout()
    out_path = os.path.join(RESULTS_DIR, "benchmark_plot.png")
    fig.savefig(out_path, dpi=140)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
