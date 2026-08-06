# Lightweight Continuous-Trust Zero Trust Layer for MQTT

Research prototype for: *Design and Performance Evaluation of a Lightweight
Zero Trust Framework for MQTT-Based Resource-Constrained IoT Networks.*

## What this actually contributes (read this before the code)

Static ABAC-based access control for MQTT is **not novel** — an
enforcement-monitor-as-proxy pattern for MQTT was published by Colombo &
Ferrari (SACMAT 2018), extended by Gabillon et al. and Alkhresheh et al.
with dynamic ABAC, and a 2026 paper on end-to-end encrypted MQTT access
control covers similar ground. This project reuses that proxy pattern
deliberately (no reason to reinvent a well-studied mechanism) and adds
the part that's still a documented open gap: **continuous, rule-based
trust re-evaluation and lightweight symmetric-key re-authentication**,
native to MQTT sessions, without the computational cost of asymmetric /
identity-based cryptography (e.g. bilinear-pairing schemes such as
SM9-based zero-trust proposals, whose authors explicitly list MQTT
integration as unfinished future work).

**Be explicit about this distinction in the write-up.** The ABAC layer =
prior art, correctly cited. The trust-scoring + re-auth layer = the
contribution being evaluated.

## Architecture

```
 MQTT client  <--TCP-->  enforcement monitor (proxy)  <--TCP-->  MQTT broker
                              |
                    policy_engine.py   (ABAC-lite: role -> topic filters)
                    trust_scorer.py    (continuous trust score, decays/recovers)
                    reauth.py          (HMAC-SHA256 short-lived tokens)
```

- `broker/` — real MQTT broker (amqtt, pure Python asyncio), plain TCP
  listener (1885) and a TLS listener (8883, self-signed cert in
  `broker/certs/`).
- `enforcement_monitor/` — the proxy (1884) and the three modules above.
- `clients/` — three client configurations used for comparison:
  `plain_client.py` (no security layer), `tls_client.py` (transport
  security only — the conventional "secure MQTT" baseline), and
  `zt_client.py` (our scheme, through the proxy, with automatic token
  refresh on forced reconnect).
- `policies/policy.yaml` — ABAC roles + trust-scoring thresholds, all in
  one auditable file.
- `policies/secrets.yaml` — pre-shared per-client HMAC secrets (stands in
  for a provisioning workflow that's out of scope for one semester).
- `experiments/run_benchmark.py` — performance evaluation (RQ3/RQ4/RQ5).
- `experiments/attack_scenarios.py` — security functional tests (RQ1/RQ2),
  covering 4 of the 10 attack scenarios in the original project scope.

## Reproducing the results

```bash
pip install -r requirements.txt
python3 experiments/run_benchmark.py      # -> results/benchmark_results.csv, benchmark_plot.png
python3 experiments/attack_scenarios.py   # -> PASS/FAIL security test summary
```

Both scripts start the broker and proxy themselves as subprocesses and
tear them down afterward — no separate setup step, no Docker required to
just run the prototype (Docker/Mosquitto were in the original tool
preferences; this implementation swapped in a pure-Python broker so the
whole pipeline runs and is testable without needing Docker Hub network
access — see "Deviations from the original tool list" below).

## Measured results (this sandbox run — see CSV for exact numbers)

| scheme | connect latency (mean) | e2e pub→sub latency (mean) | CPU (mean %) | CONNECT payload overhead |
|---|---|---|---|---|
| plain | ~3.6 ms | ~0.82 ms | ~0.38% | 0 bytes |
| tls   | ~6.7 ms | ~0.95 ms | ~0.58% | 0 bytes |
| zt (ours) | ~3.2 ms | ~1.14 ms | ~0.23% | 101 bytes |

Read this table cautiously, not triumphantly:
- These are single-run numbers on shared sandbox hardware, not averaged
  over multiple independent runs with confidence intervals — **do that
  before putting this in a paper.** `run_benchmark.py` is deterministic
  enough to just be re-run N times and aggregated.
- The trust-scoring layer only shows its cost/benefit under attack-like
  conditions (see `attack_scenarios.py`'s flood test), not in this steady
  -state comparison — the steady-state table above under-represents what
  the ZT layer is actually for. Report both.

## Limitations (state these explicitly in the paper, don't bury them)

1. **Not real constrained hardware.** This runs in a normal container/VM.
   CPU/memory numbers here are informative for relative comparison
   between schemes, not for absolute claims about microcontroller
   feasibility. If time allows, re-run the client side on a Raspberry Pi
   Zero or similar and report both.
2. **MQTT 3.1.1 has no native mid-session re-authentication.** Re-auth is
   implemented as forced DISCONNECT + required reconnect with a fresh
   token, not a protocol-level continuous-auth exchange. MQTT 5's AUTH
   packet would allow a cleaner implementation — documented as future
   work, not silently assumed away.
3. **Rule-based trust scoring, not ML-based.** Deliberate scope choice
   (see module docstring in `trust_scorer.py`) — an ML trust classifier
   is a separate, much larger project.
4. **Attack coverage is partial.** 4 of the 10 scenarios in the original
   project scope are tested (unauthorized publisher/subscriber, credential
   theft/impersonation, compromised-device flooding). Replay attack,
   privilege escalation via legitimate-but-stale tokens, and session
   hijacking are not yet covered — real gaps, not oversights to gloss over.
5. **Pre-shared secrets, not a provisioning system.** `secrets.yaml` is a
   stand-in. A real deployment needs an enrollment/rotation mechanism.

## Deviations from the original tool preferences

The original project spec preferred Eclipse Mosquitto in Docker. This
sandbox's network egress does not include Docker Hub, so the prototype
uses `amqtt` (a pure-Python asyncio MQTT broker installable from PyPI)
instead, which made the whole pipeline testable end-to-end without any
external infrastructure dependency. If you have Docker/Mosquitto
available in your own environment, swapping the broker back is a
reasonable robustness check to report ("does the overhead trend hold
against a C-implemented broker too?") — not required, but a good
addition if time permits.
