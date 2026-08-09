"""Resource sampling (real, measured) and packet-size overhead (analytical,
deterministic) helpers for the benchmark harness."""
import threading
import time
import psutil


class ResourceSampler:
    """Samples CPU% and RSS memory of a given PID on a background thread."""

    def __init__(self, pid: int, interval: float = 0.2):
        self.proc = psutil.Process(pid)
        self.interval = interval
        self.cpu_samples = []
        self.mem_samples_mb = []
        self._stop = threading.Event()
        self._thread = None
        self.proc.cpu_percent(None)  # prime the internal counter

    def _run(self):
        while not self._stop.is_set():
            self.cpu_samples.append(self.proc.cpu_percent(None))
            try:
                self.mem_samples_mb.append(self.proc.memory_info().rss / (1024 * 1024))
            except psutil.NoSuchProcess:
                break
            time.sleep(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def summary(self):
        cpu = self.cpu_samples or [0.0]
        mem = self.mem_samples_mb or [0.0]
        return {
            "cpu_mean_pct": sum(cpu) / len(cpu),
            "cpu_max_pct": max(cpu),
            "mem_mean_mb": sum(mem) / len(mem),
            "mem_max_mb": max(mem),
            "n_samples": len(cpu),
        }


def per_message_overhead_bytes(scheme: str, topic: str, client_id: str = "sensor-01",
                                role: str = "sensor") -> dict:
    """
    Deterministic, reproducible packet-size overhead calculation for the
    CONNECT packet's variable header, since this is fixed by design (token
    length, username, etc.) rather than something that needs traffic
    capture to determine. Reported alongside the measured latency/CPU
    numbers, not as a substitute for them.
    """
    topic_bytes = len(topic.encode())

    if scheme == "plain":
        username_bytes = 0
        password_bytes = 0
    elif scheme == "tls":
        # payload identical to plain at the MQTT layer; TLS record/handshake
        # overhead is separate and is captured by the measured connect
        # latency + CPU numbers, not double-counted here.
        username_bytes = 0
        password_bytes = 0
    elif scheme == "zt":
        username_bytes = len(client_id.encode())
        issued_at = str(int(time.time()))
        token = f"{client_id}:{issued_at}:{role}:" + "0" * 64  # hex digest is 64 chars
        password_bytes = len(token.encode())
    else:
        raise ValueError(scheme)

    return {
        "scheme": scheme,
        "topic_bytes": topic_bytes,
        "username_field_bytes": username_bytes,
        "password_field_bytes": password_bytes,
        "connect_payload_overhead_bytes": username_bytes + password_bytes,
    }
