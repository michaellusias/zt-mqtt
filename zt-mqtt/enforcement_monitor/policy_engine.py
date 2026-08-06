"""
ABAC-lite policy engine.

Deliberately simple and auditable: role -> allowed topic filter list.
This mirrors the enforcement-monitor pattern from Colombo & Ferrari
(SACMAT 2018) rather than reinventing access control -- the contribution
of this project is the trust-scoring / continuous re-auth layer built on
top of it (see trust_scorer.py, reauth.py), not the ABAC mechanism itself.
"""
import yaml
from pathlib import Path


def _topic_matches(filter_: str, topic: str) -> bool:
    """Standard MQTT topic-filter matching (+ single-level, # multi-level)."""
    f_parts = filter_.split("/")
    t_parts = topic.split("/")
    i = 0
    for i, fp in enumerate(f_parts):
        if fp == "#":
            return True
        if i >= len(t_parts):
            return False
        if fp == "+":
            continue
        if fp != t_parts[i]:
            return False
    return len(t_parts) == len(f_parts)


class PolicyEngine:
    def __init__(self, policy_path: str):
        with open(policy_path) as f:
            self.policy = yaml.safe_load(f)
        self.roles = self.policy["roles"]
        self.trust_cfg = self.policy["trust"]

    def _filters_for(self, role: str, client_id: str, direction: str):
        role_cfg = self.roles.get(role)
        if not role_cfg:
            return []
        filters = role_cfg.get(direction, [])
        return [f.replace("{client_id}", client_id) for f in filters]

    def can_publish(self, role: str, client_id: str, topic: str) -> bool:
        return any(_topic_matches(f, topic) for f in self._filters_for(role, client_id, "can_publish"))

    def can_subscribe(self, role: str, client_id: str, topic_filter: str) -> bool:
        return any(_topic_matches(f, topic_filter) or _topic_matches(topic_filter, f)
                    for f in self._filters_for(role, client_id, "can_subscribe"))

    def role_exists(self, role: str) -> bool:
        return role in self.roles
