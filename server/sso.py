# OpenDLP Central Server - dashboard single sign-on (OpenID Connect) - GPL-3.0-only
"""Authorization-code flow with PKCE for Microsoft Entra ID, Google Workspace, Okta, Keycloak, Authentik...

The ID token is verified against the provider's published keys (RS256 / ES256), plus iss, aud, exp and nonce.
Sessions are stateless HMAC-signed cookies; nothing is written to the database.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

Http = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]
CLOCK_SKEW = 120


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


# --------------------------------------------------------------------------- signed cookies
def sign(payload: dict[str, Any], secret: bytes) -> str:
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    mac = b64u(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def unsign(value: str | None, secret: bytes, now: float | None = None) -> dict[str, Any] | None:
    if not value or value.count(".") != 1:
        return None
    body, mac = value.split(".")
    if not hmac.compare_digest(b64u(hmac.new(secret, body.encode(), hashlib.sha256).digest()), mac):
        return None
    try:
        data = json.loads(b64u_dec(body))
    except ValueError:
        return None
    if not isinstance(data, dict) or float(data.get("exp", 0)) < (now or time.time()):
        return None
    return data


# --------------------------------------------------------------------------- role mapping
def _parse_list(raw: str) -> list[str]:
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def role_for(email: str, admins: str, viewers: str) -> str | None:
    """Entries are full addresses or '@domain'. Admin wins over viewer. Unlisted users are refused."""
    email = email.strip().lower()
    if "@" not in email:
        return None
    domain = "@" + email.rsplit("@", 1)[1]
    for role, raw in (("admin", admins), ("viewer", viewers)):
        entries = _parse_list(raw)
        if email in entries or domain in entries:
            return role
    return None


# --------------------------------------------------------------------------- provider
@dataclass
class Provider:
    issuer: str
    client_id: str
    client_secret: str
    http: Http
    _config: dict[str, Any] | None = None
    _jwks: dict[str, Any] = field(default_factory=dict)
    _jwks_at: float = 0.0

    def config(self) -> dict[str, Any]:
        if self._config is None:
            st, data = self.http("GET", self.issuer.rstrip("/") + "/.well-known/openid-configuration", {}, None)
            if st != 200:
                raise RuntimeError(f"OIDC discovery failed: HTTP {st}")
            cfg = json.loads(data)
            if cfg.get("issuer", "").rstrip("/") != self.issuer.rstrip("/"):
                raise RuntimeError("OIDC discovery returned a different issuer; use the tenant-specific issuer URL")
            self._config = cfg
        return self._config

    def authorize_url(self, redirect_uri: str, state: str, nonce: str, verifier: str) -> str:
        challenge = b64u(hashlib.sha256(verifier.encode()).digest())
        q = {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri,
            "scope": "openid email profile", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        return self.config()["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)

    def exchange(self, code: str, redirect_uri: str, verifier: str) -> str:
        body = urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": self.client_id, "client_secret": self.client_secret, "code_verifier": verifier,
        }).encode()
        st, data = self.http("POST", self.config()["token_endpoint"],
                             {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, body)
        if st != 200:
            raise RuntimeError(f"OIDC token exchange failed: HTTP {st}")
        tok = json.loads(data).get("id_token")
        if not tok:
            raise RuntimeError("OIDC provider returned no id_token")
        return tok

    def _key(self, kid: str | None):
        if not self._jwks or (kid and kid not in self._jwks and time.time() - self._jwks_at > 60):
            st, data = self.http("GET", self.config()["jwks_uri"], {}, None)
            if st != 200:
                raise RuntimeError(f"OIDC key download failed: HTTP {st}")
            self._jwks = {k.get("kid"): k for k in json.loads(data).get("keys", [])}
            self._jwks_at = time.time()
        if kid in self._jwks:
            return self._jwks[kid]
        if kid is None and len(self._jwks) == 1:
            return next(iter(self._jwks.values()))
        raise RuntimeError("ID token signed with an unknown key")

    def verify(self, id_token: str, nonce: str, now: float | None = None) -> dict[str, Any]:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        try:
            h_b64, c_b64, s_b64 = id_token.split(".")
            header, claims, sig = json.loads(b64u_dec(h_b64)), json.loads(b64u_dec(c_b64)), b64u_dec(s_b64)
        except ValueError as exc:
            raise RuntimeError("Malformed ID token") from exc
        jwk = self._key(header.get("kid"))
        signed = f"{h_b64}.{c_b64}".encode()
        alg = header.get("alg")
        try:
            if alg == "RS256" and jwk.get("kty") == "RSA":
                key = rsa.RSAPublicNumbers(int.from_bytes(b64u_dec(jwk["e"]), "big"),
                                           int.from_bytes(b64u_dec(jwk["n"]), "big")).public_key()
                key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256" and len(sig) == 64:
                key = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(jwk["x"]), "big"),
                                                    int.from_bytes(b64u_dec(jwk["y"]), "big"), ec.SECP256R1()).public_key()
                der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
                key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
            else:
                raise RuntimeError(f"Unsupported ID token algorithm {alg!r}")
        except InvalidSignature as exc:
            raise RuntimeError("ID token signature is invalid") from exc

        now = now or time.time()
        aud = claims.get("aud")
        if str(claims.get("iss", "")).rstrip("/") != self.config()["issuer"].rstrip("/"):
            raise RuntimeError("ID token issuer mismatch")
        if not (aud == self.client_id or (isinstance(aud, list) and self.client_id in aud)):
            raise RuntimeError("ID token audience mismatch")
        if float(claims.get("exp", 0)) + CLOCK_SKEW < now:
            raise RuntimeError("ID token expired")
        if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise RuntimeError("ID token nonce mismatch")
        return claims


def email_of(claims: dict[str, Any]) -> str:
    # Google/Okta: email (+ email_verified). Entra ID: email may be absent; preferred_username / upn is the sign-in name.
    if claims.get("email") and claims.get("email_verified", True) is not False:
        return str(claims["email"])
    return str(claims.get("preferred_username") or claims.get("upn") or "")


def new_login() -> dict[str, str]:
    return {"state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24), "verifier": secrets.token_urlsafe(48)}
