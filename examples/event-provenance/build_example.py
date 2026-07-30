#!/usr/bin/env python3
"""
Build the worked example for the CDEvents event-provenance guide.

Generates, in the current directory:
  - keys/ed25519_private.pem, keys/ed25519_public.pem  (throwaway DEMO key)
  - event.json               a valid dev.cdevents.artifact.published CDEvent
  - event.canonical.json     RFC 8785 (JCS) canonical serialization of event.json
  - commitment.json          {alg, hash} = SHA-256 over the canonical bytes
  - envelope.json            DSSE envelope signing the canonical bytes
  - event.tampered.json      the same event with one byte-of-meaning changed
  - envelope.tampered.json   original signature, payload swapped to the tampered bytes

Nothing here is vendor-specific. The commitment hash is just the event digest;
WHERE it is anchored (a transparency log, an RFC 3161 TSA, a blockchain, ...) is an
implementation choice and is intentionally out of scope for this example.

Requires: rfc8785, cryptography, jsonschema
"""
import base64
import hashlib
import json
import os
import urllib.request

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from jsonschema import Draft202012Validator

PAYLOAD_TYPE = "application/cdevents+json"
CDEVENTS_TAG = "v0.5.1"
SCHEMA_URL = f"https://raw.githubusercontent.com/cdevents/spec/{CDEVENTS_TAG}/schemas/artifactpublished.json"

HERE = os.path.dirname(os.path.abspath(__file__))
KEYDIR = os.path.join(HERE, "keys")
os.makedirs(KEYDIR, exist_ok=True)


def jcs(obj) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme -> canonical UTF-8 bytes."""
    return rfc8785.dumps(obj)


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (secure-systems-lab/dsse protocol.md).

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    LEN(s) = ASCII decimal byte length, no leading zeros; SP = 0x20.
    """
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


def keyid_for(pub_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub_raw).hexdigest()


# ---- 1. the CDEvent (a real dev.cdevents.artifact.published event) ----------
event = {
    "context": {
        "specversion": "0.5.1",
        "id": "271069a8-fc18-44f1-b38f-9d70a1695819",
        "source": "/pipelines/release/build-and-publish",
        "type": "dev.cdevents.artifact.published.0.3.0",
        "timestamp": "2026-07-03T14:27:05.315384Z",
    },
    "subject": {
        "id": "pkg:oci/myapp@sha256:0f7e1b2c3d4a5b6c7d8e9f00112233445566778899aabbccddeeff0011223344",
        "source": "/pipelines/release/build-and-publish",
        "content": {
            "sbom": {"uri": "https://sbom.example.com/myorg/myapp/0f7e1b2c.spdx.json"},
            "user": "release-bot",
        },
    },
}

# ---- 2. validate it against the REAL CDEvents schema -----------------------
with urllib.request.urlopen(SCHEMA_URL, timeout=30) as r:
    schema = json.load(r)
Draft202012Validator(schema).validate(event)
print(f"[ok] event validates against CDEvents {CDEVENTS_TAG} artifact-published schema")

# ---- 3. canonicalize + digest (the "commitment") ---------------------------
canonical = jcs(event)
digest = hashlib.sha256(canonical).hexdigest()
commitment = {
    "alg": "RFC8785-JCS+SHA-256",
    "hash": f"sha256:{digest}",
    "note": (
        "SHA-256 over the RFC 8785 (JCS) canonical serialization of the CDEvent. "
        "This is the value an emitter would commit to an external timeline. "
        "The anchor (transparency log, RFC 3161 TSA, blockchain, ...) is out of scope."
    ),
}

# ---- 4. DSSE sign the canonical bytes --------------------------------------
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
pub_raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
kid = keyid_for(pub_raw)

signature = priv.sign(pae(PAYLOAD_TYPE, canonical))
envelope = {
    "payload": base64.standard_b64encode(canonical).decode(),
    "payloadType": PAYLOAD_TYPE,
    "signatures": [{"keyid": kid, "sig": base64.standard_b64encode(signature).decode()}],
}

# persist the DEMO keypair so the example is reproducible + verifiable
with open(os.path.join(KEYDIR, "ed25519_private.pem"), "wb") as f:
    f.write(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
with open(os.path.join(KEYDIR, "ed25519_public.pem"), "wb") as f:
    f.write(pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

# ---- 5. a tampered event + a tampered envelope -----------------------------
tampered_event = json.loads(json.dumps(event))
tampered_event["subject"]["content"]["user"] = "attacker-bot"  # one field of meaning
tampered_canonical = jcs(tampered_event)
# attacker swaps the payload but cannot re-sign (no private key): keep original sig
tampered_envelope = json.loads(json.dumps(envelope))
tampered_envelope["payload"] = base64.standard_b64encode(tampered_canonical).decode()

# ---- 6. write everything ----------------------------------------------------
def write(name, data, raw=False):
    p = os.path.join(HERE, name)
    with open(p, "wb" if raw else "w") as f:
        if raw:
            f.write(data)
        else:
            json.dump(data, f, indent=2)
            f.write("\n")
    print(f"[wrote] {name}")

write("event.json", event)
write("event.canonical.json", canonical, raw=True)
write("commitment.json", commitment)
write("envelope.json", envelope)
write("event.tampered.json", tampered_event)
write("envelope.tampered.json", tampered_envelope)

print(f"\nkeyid    = {kid}")
print(f"digest   = sha256:{digest}")
print("done.")
