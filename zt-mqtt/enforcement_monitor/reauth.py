"""
Lightweight symmetric-key re-authentication tokens.

Design goal: give the continuous-verification layer a way to force a
cheap, short-lived proof of continued identity WITHOUT the computational
cost of asymmetric / identity-based cryptography (e.g. the SM9 bilinear
pairing scheme used in heavier zero-trust proposals). HMAC-SHA256 over a
pre-shared per-client secret is cheap enough to be plausible on
constrained microcontrollers, which is the whole point of this design.

Token format (all client-supplied, carried in the MQTT password field):
    "<client_id>:<issued_at>:<role>:<hmac_hex>"

This is a research prototype, not a production credential system:
- Pre-shared secrets stand in for a real provisioning/PKI process.
- No replay-window persistence across proxy restarts.
"""
import hmac
import hashlib
import time
from typing import Optional, Tuple


class ReauthManager:
    def __init__(self, shared_secrets: dict, token_lifetime_seconds: int = 30):
        """shared_secrets: {client_id: secret_str} -- pre-provisioned."""
        self.shared_secrets = shared_secrets
        self.token_lifetime = token_lifetime_seconds

    def issue_token(self, client_id: str, role: str) -> str:
        secret = self.shared_secrets.get(client_id, "").encode()
        issued_at = str(int(time.time()))
        msg = f"{client_id}:{issued_at}:{role}".encode()
        digest = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        return f"{client_id}:{issued_at}:{role}:{digest}"

    def verify_token(self, client_id: str, token: str) -> Tuple[bool, Optional[str]]:
        """Returns (is_valid, role_if_valid)."""
        try:
            tok_client_id, issued_at, role, digest = token.split(":")
        except (ValueError, AttributeError):
            return False, None

        if tok_client_id != client_id:
            return False, None

        secret = self.shared_secrets.get(client_id)
        if secret is None:
            return False, None

        expected_msg = f"{tok_client_id}:{issued_at}:{role}".encode()
        expected_digest = hmac.new(secret.encode(), expected_msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_digest, digest):
            return False, None

        if time.time() - int(issued_at) > self.token_lifetime:
            return False, None  # expired -> forces a fresh reauth, not just a static replay

        return True, role
