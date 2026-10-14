#!/usr/bin/env python3
"""Generate an ECDSA P-256 key pair for asymmetric policy signing.

  python tools/gen_signing_key.py /etc/leakwarden/policy-signing.pem

Keep the private key on the server only (LEAKWARDEN_SIGNING_KEY). Put the printed PUBLIC key
into each agent's agent.config.json as "PolicySigningPublicKey" (single line with \\n escapes
or a JSON string with real newlines).
"""
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

out = Path(sys.argv[1] if len(sys.argv) > 1 else "policy-signing.pem")
key = ec.generate_private_key(ec.SECP256R1())
out.write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
try:
    out.chmod(0o600)
except OSError:
    pass
pub = key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
print(f"Private key written to {out} (keep secret, server only)\n")
print("Public key for agent.config.json \"PolicySigningPublicKey\":\n")
print(pub)
