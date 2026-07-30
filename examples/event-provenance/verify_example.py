#!/usr/bin/env python3
"""
Verify the worked example end to end.

For the genuine artifacts (envelope.json + commitment.json) this shows:
  (a) the DSSE signature verifies against the public key, and
  (b) the SHA-256 of the (canonical) signed payload equals the committed hash.

For the tampered artifacts (envelope.tampered.json) it shows the SAME checks
fail: the DSSE signature no longer verifies AND the recomputed hash no longer
matches the commitment. An attacker who alters the event cannot re-sign it
(no private key) and cannot make the digest match the pre-existing commitment.

Standards used:
  - DSSE  : secure-systems-lab/dsse, protocol.md (PAE + envelope shape)
  - JCS   : RFC 8785 (JSON Canonicalization Scheme)
  - CDEvents cloudevents-binding.md (transport), artifact-published schema (shape)

Requires: rfc8785, cryptography
Exit code 0 iff genuine passes both checks AND tampered fails both.
"""
import base64
import hashlib
import json
import os
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: DSSEv1 SP LEN(t) SP t SP LEN(b) SP b."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


def load(name):
    with open(os.path.join(HERE, name), "rb") as f:
        return f.read()


def load_pubkey():
    return serialization.load_pem_public_key(load("keys/ed25519_public.pem"))


def dsse_verify(envelope: dict, pub: Ed25519PublicKey) -> bool:
    """Verify at least one signature in the envelope (DSSE protocol)."""
    body = base64.standard_b64decode(envelope["payload"])
    msg = pae(envelope["payloadType"], body)
    for s in envelope["signatures"]:
        try:
            pub.verify(base64.standard_b64decode(s["sig"]), msg)
            return True
        except InvalidSignature:
            continue
    return False


def hash_matches(envelope: dict, commitment: dict) -> (bool, str):
    """Recompute SHA-256 over the signed payload bytes; compare to commitment.

    Per DSSE guidance we hash the exact verified bytes; we do NOT re-canonicalize.
    Those bytes already ARE the RFC 8785 canonical form the emitter committed to.
    """
    body = base64.standard_b64decode(envelope["payload"])
    got = "sha256:" + hashlib.sha256(body).hexdigest()
    return (got == commitment["hash"], got)


def show(title, envelope, commitment, pub):
    print(f"--- {title} ---")
    sig_ok = dsse_verify(envelope, pub)
    h_ok, got = hash_matches(envelope, commitment)
    print(f"  DSSE signature : {'VALID  ' if sig_ok else 'INVALID'}  (payloadType={envelope['payloadType']})")
    print(f"  committed hash : {commitment['hash']}")
    print(f"  recomputed hash: {got}")
    print(f"  hash match     : {'YES' if h_ok else 'NO'}")
    return sig_ok, h_ok


def main():
    pub = load_pubkey()
    commitment = json.loads(load("commitment.json"))

    genuine = json.loads(load("envelope.json"))
    tampered = json.loads(load("envelope.tampered.json"))

    print("CDEvents event-provenance worked example -- verification\n")
    g_sig, g_hash = show("GENUINE event (envelope.json)", genuine, commitment, pub)
    print()
    t_sig, t_hash = show("TAMPERED event (envelope.tampered.json)", tampered, commitment, pub)

    print("\nExpected: genuine passes BOTH checks; tampered fails BOTH.")
    ok = g_sig and g_hash and (not t_sig) and (not t_hash)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
