"""
Our scheme: connects through the enforcement monitor proxy (1884), using
a short-lived HMAC token as the MQTT password. When the proxy forces a
disconnect (trust decayed below threshold, or token expired -- see
trust_scorer.py / proxy.py), this client transparently mints a fresh
token and reconnects, so the "continuous re-authentication" behavior is
visible end-to-end rather than just inside the proxy.
"""
import time
import threading
import yaml
import paho.mqtt.client as mqtt

from enforcement_monitor.reauth import ReauthManager

PROXY_HOST, PROXY_PORT = "127.0.0.1", 1884


def _load_client_creds(client_id: str):
    with open("policies/secrets.yaml") as f:
        cfg = yaml.safe_load(f)
    entry = cfg["clients"][client_id]
    return entry["secret"], entry["role"]


class ZTClient:
    def __init__(self, client_id: str, token_lifetime=30):
        self.client_id = client_id
        self.secret, self.role = _load_client_creds(client_id)
        self.reauth = ReauthManager({client_id: self.secret}, token_lifetime)
        self.client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.connected = threading.Event()
        self.reconnect_count = 0
        self._auto_reconnect = True

    def _fresh_credentials(self):
        token = self.reauth.issue_token(self.client_id, self.role)
        self.client.username_pw_set(username=self.client_id, password=token)

    def _on_connect(self, c, userdata, flags, rc):
        if rc == 0:
            self.connected.set()

    def _on_disconnect(self, c, userdata, rc):
        self.connected.clear()
        if self._auto_reconnect and rc != 0:
            self.reconnect_count += 1
            self._fresh_credentials()
            try:
                self.client.reconnect()
            except OSError:
                pass

    def connect_and_time(self, timeout=5.0):
        self._fresh_credentials()
        t0 = time.perf_counter()
        self.client.connect(PROXY_HOST, PROXY_PORT, keepalive=30)
        self.client.loop_start()
        if not self.connected.wait(timeout):
            raise TimeoutError("connect timed out (rejected by enforcement monitor?)")
        return time.perf_counter() - t0

    def stop(self):
        self._auto_reconnect = False
        self.client.disconnect()  # skip loop_stop(): its internal join waits up to paho's ~1s select timeout
