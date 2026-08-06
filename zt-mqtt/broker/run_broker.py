"""
Starts a real MQTT broker (amqtt, pure-Python asyncio broker) with two
listeners:
  - plain TCP on 1885   (used directly by the plain baseline, and as the
                          upstream broker the enforcement-monitor proxy
                          forwards validated traffic to)
  - TLS on 8883          (used directly by the TLS baseline)

Using a real broker (rather than mocking one) means every latency/CPU/
bandwidth number the benchmark reports is an actually-measured number
from running code, not an assumed or fabricated one. The trade-off,
stated for the write-up: this runs in a normal container/VM, not on
genuinely constrained hardware (e.g. an ESP32 or Cortex-M class MCU) --
call this out explicitly as a threat to external validity in the paper.
"""
import asyncio
import logging
from amqtt.broker import Broker

logging.basicConfig(level=logging.INFO, format="%(asctime)s [broker] %(message)s")

CONFIG = {
    "listeners": {
        "default": {"type": "tcp", "bind": "127.0.0.1:1885"},
        "tls": {
            "type": "tcp",
            "bind": "127.0.0.1:8883",
            "ssl": True,
            "cafile": "broker/certs/server.crt",
            "certfile": "broker/certs/server.crt",
            "keyfile": "broker/certs/server.key",
        },
    },
    "plugins": {
        "amqtt.plugins.authentication.AnonymousAuthPlugin": {"allow_anonymous": True},
    },
}


async def main():
    broker = Broker(config=CONFIG)
    await broker.start()
    await asyncio.Event().wait()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
