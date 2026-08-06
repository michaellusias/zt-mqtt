"""Baseline 2: MQTT over TLS. Conventional 'secure MQTT' baseline that
existing literature (e.g. TLS-based MQTT deployments) is typically
compared against. No ABAC/trust layer on top -- transport security only."""
import ssl
import time
import threading
import paho.mqtt.client as mqtt

BROKER_HOST, BROKER_PORT = "localhost", 8883  # must match cert CN for hostname verification
CA_CERT = "broker/certs/server.crt"


def make_client(client_id: str) -> mqtt.Client:
    c = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
    c.tls_set(ca_certs=CA_CERT, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    return c


def connect_and_time(client: mqtt.Client, host=BROKER_HOST, port=BROKER_PORT, timeout=5.0):
    connected = threading.Event()

    def on_connect(c, userdata, flags, rc):
        connected.set()

    client.on_connect = on_connect
    t0 = time.perf_counter()
    client.connect(host, port, keepalive=30)
    client.loop_start()
    if not connected.wait(timeout):
        raise TimeoutError("connect timed out (TLS handshake failed?)")
    return time.perf_counter() - t0
