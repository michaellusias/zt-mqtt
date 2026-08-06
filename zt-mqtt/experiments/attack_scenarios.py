"""
Security evaluation against a subset of the attack scenarios named in the
project scope: unauthorized publisher, unauthorized subscriber, credential
theft/misuse, and a compromised/flooding device (rate anomaly). Each test
asserts an expected outcome and reports PASS/FAIL -- this is a security
functional test, not a performance benchmark (see run_benchmark.py for
that).

Not covered here (documented as future work, not silently skipped):
replay attack, privilege escalation, session hijacking, device
impersonation via cloned credentials. These need either MQTT 5 support
or a more elaborate token/session design than this prototype implements.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.run_benchmark import wait_for_port


def scenario_unauthorized_publisher():
    """A client with role=sensor tries to publish outside its own topic
    namespace (e.g. impersonating another sensor's topic). Expected: the
    proxy silently drops the PUBLISH (does not forward to broker)."""
    from clients.zt_client import ZTClient
    import paho.mqtt.client as mqtt

    sub_received = []
    z_sub = ZTClient("dashboard-01")

    def on_message(c, userdata, msg):
        sub_received.append(msg.topic)

    z_sub.client.on_message = on_message
    z_sub.connect_and_time()
    z_sub.client.subscribe("sensors/#", qos=1)
    time.sleep(0.3)

    z_pub = ZTClient("sensor-01")
    z_pub.connect_and_time()
    # sensor-01 is only allowed to publish to sensors/sensor-01/#
    z_pub.client.publish("sensors/sensor-02/spoofed", payload="malicious", qos=1)
    time.sleep(0.5)

    z_pub.stop()
    z_sub.stop()

    passed = "sensors/sensor-02/spoofed" not in sub_received
    print(f"[{'PASS' if passed else 'FAIL'}] unauthorized_publisher: "
          f"spoofed message {'blocked' if passed else 'WAS FORWARDED'}")
    return passed


def scenario_wrong_credentials():
    """An attacker who knows a legitimate client_id (client IDs are not
    secret) but does NOT know that client's HMAC secret tries to connect,
    impersonating it with a forged token. Models credential theft where
    the attacker has reconnaissance but not the actual key material.
    Expected: CONNECT rejected (HMAC verification fails)."""
    import paho.mqtt.client as mqtt
    from enforcement_monitor.reauth import ReauthManager
    import threading

    real_client_id = "sensor-01"  # attacker knows this id, but not its real secret
    forged = ReauthManager({real_client_id: "totally-wrong-guessed-secret"})
    token = forged.issue_token(real_client_id, "admin")  # also tries to escalate role while at it

    c = mqtt.Client(client_id=real_client_id, protocol=mqtt.MQTTv311)
    c.username_pw_set(username=real_client_id, password=token)
    connected = threading.Event()
    rejected = threading.Event()

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            connected.set()
        else:
            rejected.set()

    c.on_connect = on_connect
    c.connect("127.0.0.1", 1884, keepalive=30)
    c.loop_start()
    time.sleep(2.0)
    c.loop_stop()
    try:
        c.disconnect()
    except Exception:
        pass

    passed = not connected.is_set()
    print(f"[{'PASS' if passed else 'FAIL'}] wrong_credentials: "
          f"forged token {'correctly rejected' if passed else 'was ACCEPTED'}")
    return passed


def scenario_unauthorized_subscriber():
    """A sensor-role client (which has can_subscribe: [] in policy.yaml)
    attempts to subscribe to the aggregate topic space. Expected: SUBACK
    failure / no messages ever delivered to it."""
    from clients.zt_client import ZTClient

    received = []
    z = ZTClient("sensor-01")
    z.client.on_message = lambda c, u, m: received.append(m.topic)
    z.connect_and_time()
    z.client.subscribe("aggregates/#", qos=1)
    time.sleep(0.3)

    z2 = ZTClient("aggregator-01")
    z2.connect_and_time()
    z2.client.publish("aggregates/aggregator-01/summary", payload="secret-rollup", qos=1)
    time.sleep(0.5)

    z.stop()
    z2.stop()
    passed = len(received) == 0
    print(f"[{'PASS' if passed else 'FAIL'}] unauthorized_subscriber: "
          f"{'no data leaked' if passed else 'DATA WAS DELIVERED'}")
    return passed


def scenario_flood_triggers_reauth():
    """A compromised/misbehaving device publishes far above the configured
    rate threshold. Expected: trust score decays and the proxy forces a
    disconnect/reauth (visible as reconnect_count > 0 on the client)."""
    from clients.zt_client import ZTClient

    z = ZTClient("sensor-01")
    z.connect_and_time()
    for _ in range(150):
        z.client.publish("sensors/sensor-01/flood", payload="x", qos=0)
    time.sleep(1.5)
    passed = z.reconnect_count > 0
    print(f"[{'PASS' if passed else 'FAIL'}] flood_triggers_reauth: "
          f"reconnects forced by trust engine = {z.reconnect_count}")
    z.stop()
    return passed


def main():
    print("starting broker + enforcement monitor...")
    broker = subprocess.Popen([sys.executable, "broker/run_broker.py"])
    wait_for_port("127.0.0.1", 1885)
    proxy = subprocess.Popen([sys.executable, "-m", "enforcement_monitor.proxy"])
    wait_for_port("127.0.0.1", 1884)
    time.sleep(0.5)

    results = {}
    try:
        results["unauthorized_publisher"] = scenario_unauthorized_publisher()
        results["wrong_credentials"] = scenario_wrong_credentials()
        results["unauthorized_subscriber"] = scenario_unauthorized_subscriber()
        results["flood_triggers_reauth"] = scenario_flood_triggers_reauth()
    finally:
        proxy.terminate()
        broker.terminate()
        proxy.wait(timeout=5)
        broker.wait(timeout=5)

    print("\n=== summary ===")
    for name, ok in results.items():
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
    n_pass = sum(results.values())
    print(f"{n_pass}/{len(results)} scenarios passed")


if __name__ == "__main__":
    main()
