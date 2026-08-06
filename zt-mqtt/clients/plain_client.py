"""Baseline 1: plain MQTT, no TLS, no auth, no ABAC/trust layer."""
import time
import threading
import paho.mqtt.client as mqtt

BROKER_HOST, BROKER_PORT = "127.0.0.1", 1885


def make_client(client_id: str) -> mqtt.Client:
    return mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)


def connect_and_time(client: mqtt.Client, host=BROKER_HOST, port=BROKER_PORT, timeout=5.0):
    """Returns connect latency in seconds (time to on_connect callback)."""
    connected = threading.Event()

    def on_connect(c, userdata, flags, rc):
        connected.set()

    client.on_connect = on_connect
    t0 = time.perf_counter()
    client.connect(host, port, keepalive=30)
    client.loop_start()
    if not connected.wait(timeout):
        raise TimeoutError("connect timed out")
    return time.perf_counter() - t0
