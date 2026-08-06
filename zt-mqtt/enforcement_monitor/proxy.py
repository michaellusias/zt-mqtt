"""
Enforcement monitor: an async TCP proxy between MQTT clients and a real
broker (amqtt, listening locally). Architecture follows the
enforcement-monitor-as-proxy pattern (Colombo & Ferrari, SACMAT 2018);
the contribution here is layering continuous trust scoring and forced
symmetric-key re-authentication on top of static ABAC (see
trust_scorer.py / reauth.py for the parts that are actually new).

Limitations, stated plainly (do not remove when writing this up):
- MQTT 3.1.1 has no native mid-session re-authentication primitive
  (MQTT 5 does, via AUTH packets, but this prototype targets 3.1.1 for
  broker/library compatibility). Re-auth is therefore implemented as a
  forced DISCONNECT + required reconnect with a fresh token. This is an
  honest simplification, not a claim of protocol-level continuous auth.
- Only the first SUBSCRIBE topic filter in a packet is authorized; a
  packet with N filters is treated as authorizing the first only. Fine
  for this benchmark's traffic pattern, would need extending for
  general use.
- Pre-shared per-client HMAC secrets stand in for a real provisioning
  workflow (out of scope for one semester).
"""
import asyncio
import logging
import time

from enforcement_monitor import mqtt_packet as mp
from enforcement_monitor.policy_engine import PolicyEngine
from enforcement_monitor.trust_scorer import TrustScorer
from enforcement_monitor.reauth import ReauthManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [proxy] %(message)s")
log = logging.getLogger("proxy")


class EnforcementMonitor:
    def __init__(self, policy_path: str, shared_secrets: dict,
                 listen_host="127.0.0.1", listen_port=1884,
                 broker_host="127.0.0.1", broker_port=1885):
        self.policy = PolicyEngine(policy_path)
        self.trust = TrustScorer(self.policy.trust_cfg)
        self.reauth = ReauthManager(shared_secrets, self.policy.trust_cfg["reauth_token_lifetime_seconds"])
        self.listen_host, self.listen_port = listen_host, listen_port
        self.broker_host, self.broker_port = broker_host, broker_port
        # metrics hooks, populated for benchmarking
        self.metrics = {"auth_decisions": [], "authz_decisions": []}

    async def start(self):
        server = await asyncio.start_server(self._handle_client, self.listen_host, self.listen_port)
        log.info(f"listening on {self.listen_host}:{self.listen_port} -> broker {self.broker_host}:{self.broker_port}")
        async with server:
            await server.serve_forever()

    async def _handle_client(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter):
        peer = c_writer.get_extra_info("peername")
        buf = b""

        # ---- Read the CONNECT packet and authenticate before touching the broker ----
        t0 = time.perf_counter()
        while True:
            chunk = await c_reader.read(4096)
            if not chunk:
                c_writer.close()
                return
            buf += chunk
            pkt = mp.try_parse(buf)
            if pkt:
                break

        if pkt.packet_type != mp.CONNECT:
            log.warning(f"{peer}: first packet was not CONNECT, dropping")
            c_writer.close()
            return

        client_id = pkt.client_id
        token = pkt.password or ""
        valid, role = self.reauth.verify_token(client_id, token)
        auth_latency = time.perf_counter() - t0
        self.metrics["auth_decisions"].append({"client_id": client_id, "valid": valid, "latency_s": auth_latency})

        if not valid or not self.policy.role_exists(role):
            self.trust.record_auth_failure(client_id)
            c_writer.write(mp.build_connack(return_code=5))  # not authorized
            await c_writer.drain()
            c_writer.close()
            log.info(f"{peer} client_id={client_id}: AUTH REJECTED")
            return

        self.trust.mark_reauthenticated(client_id)
        buf = buf[pkt.total_len:]  # consume the CONNECT bytes; keep any pipelined leftovers

        # ---- Connect to the real broker and forward the (validated) CONNECT ----
        try:
            b_reader, b_writer = await asyncio.open_connection(self.broker_host, self.broker_port)
        except OSError as e:
            log.error(f"cannot reach broker: {e}")
            c_writer.close()
            return

        b_writer.write(pkt.raw)
        await b_writer.drain()

        log.info(f"{peer} client_id={client_id} role={role}: AUTH OK, forwarded CONNECT")

        # ---- Pump broker->client unmodified; inspect client->broker ----
        async def broker_to_client():
            try:
                while True:
                    data = await b_reader.read(4096)
                    if not data:
                        break
                    c_writer.write(data)
                    await c_writer.drain()
            except (ConnectionResetError, asyncio.CancelledError):
                pass

        async def client_to_broker():
            nonlocal buf
            try:
                while True:
                    if not buf:
                        data = await c_reader.read(4096)
                        if not data:
                            break
                        buf += data

                    while True:
                        pkt2 = mp.try_parse(buf)
                        if not pkt2:
                            break
                        buf = buf[pkt2.total_len:]

                        forward = True
                        t1 = time.perf_counter()

                        if pkt2.packet_type == mp.PUBLISH:
                            allowed = self.policy.can_publish(role, client_id, pkt2.topic)
                            self.trust.record_message(client_id)
                            forward = allowed
                            self.metrics["authz_decisions"].append(
                                {"client_id": client_id, "topic": pkt2.topic, "op": "publish",
                                 "allowed": allowed, "latency_s": time.perf_counter() - t1})
                            if not allowed:
                                log.info(f"client_id={client_id}: PUBLISH to {pkt2.topic} DENIED (role={role})")

                        elif pkt2.packet_type == mp.SUBSCRIBE:
                            allowed = self.policy.can_subscribe(role, client_id, pkt2.topic)
                            self.trust.record_message(client_id)
                            self.metrics["authz_decisions"].append(
                                {"client_id": client_id, "topic": pkt2.topic, "op": "subscribe",
                                 "allowed": allowed, "latency_s": time.perf_counter() - t1})
                            if not allowed:
                                forward = False
                                log.info(f"client_id={client_id}: SUBSCRIBE to {pkt2.topic} DENIED (role={role})")

                        if forward:
                            b_writer.write(pkt2.raw)
                            await b_writer.drain()

                        # Continuous verification: force reconnect+reauth if trust has decayed
                        if self.trust.needs_disconnect(client_id):
                            log.info(f"client_id={client_id}: trust score too low, forcing DISCONNECT")
                            c_writer.close()
                            b_writer.close()
                            return
                        if self.trust.needs_reauth(client_id):
                            log.info(f"client_id={client_id}: forcing re-auth (score/token expiry)")
                            c_writer.close()
                            b_writer.close()
                            return
            except (ConnectionResetError, asyncio.CancelledError):
                pass

        await asyncio.gather(broker_to_client(), client_to_broker(), return_exceptions=True)
        c_writer.close()
        b_writer.close()


if __name__ == "__main__":
    import yaml
    with open("policies/secrets.yaml") as f:
        secrets_file = yaml.safe_load(f)
    monitor = EnforcementMonitor("policies/policy.yaml", secrets_file["secrets"])
    asyncio.run(monitor.start())
