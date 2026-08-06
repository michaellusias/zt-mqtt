"""
Continuous, rule-based trust scoring per connected client.

This is the piece that turns "ABAC access control for MQTT" (well-studied
since Colombo & Ferrari 2018) into something closer to an actual Zero
Trust posture: trust is not a one-time CONNECT-time decision, it decays
and recovers over the life of the session based on observed behavior, and
crossing a threshold forces re-authentication or disconnection.

Deliberately rule-based / weighted-sum rather than ML-based: an ML trust
classifier is a much larger commitment (labeled data, training,
validation) that is out of scope for a one-semester undergraduate project
and would not be a fair fight against papers that already report high
accuracy figures for that approach. A transparent, auditable rule engine
is also arguably a better fit for a security-critical decision anyway.
"""
import time
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class ClientTrustState:
    score: float
    last_window_start: float
    msgs_in_window: int = 0
    auth_failures: int = 0
    rate_violations: int = 0
    last_reauth_time: float = field(default_factory=time.time)


class TrustScorer:
    def __init__(self, trust_cfg: dict):
        self.cfg = trust_cfg
        self.state: Dict[str, ClientTrustState] = {}

    def _get(self, client_id: str) -> ClientTrustState:
        if client_id not in self.state:
            self.state[client_id] = ClientTrustState(
                score=self.cfg["initial_score"],
                last_window_start=time.time(),
            )
        return self.state[client_id]

    def record_auth_failure(self, client_id: str):
        st = self._get(client_id)
        st.auth_failures += 1
        st.score = max(self.cfg["min_score"], st.score - self.cfg["decay_per_auth_failure"])

    def record_message(self, client_id: str) -> None:
        """Call on every PUBLISH/SUBSCRIBE; applies the sliding-window rate check."""
        st = self._get(client_id)
        now = time.time()
        window = self.cfg["window_seconds"]

        if now - st.last_window_start > window:
            # window elapsed cleanly -> small trust recovery, reset counters
            if st.msgs_in_window <= self.cfg["max_msgs_per_window"]:
                st.score = min(self.cfg["max_score"], st.score + self.cfg["recovery_per_clean_window"])
            st.last_window_start = now
            st.msgs_in_window = 0

        st.msgs_in_window += 1
        if st.msgs_in_window > self.cfg["max_msgs_per_window"]:
            st.rate_violations += 1
            st.score = max(self.cfg["min_score"], st.score - self.cfg["decay_per_rate_violation"])

    def score(self, client_id: str) -> float:
        return self._get(client_id).score

    def needs_reauth(self, client_id: str) -> bool:
        st = self._get(client_id)
        token_expired = (time.time() - st.last_reauth_time) > self.cfg["reauth_token_lifetime_seconds"]
        return st.score < self.cfg["reauth_threshold"] or token_expired

    def needs_disconnect(self, client_id: str) -> bool:
        return self._get(client_id).score < self.cfg["disconnect_threshold"]

    def mark_reauthenticated(self, client_id: str):
        st = self._get(client_id)
        st.last_reauth_time = time.time()
