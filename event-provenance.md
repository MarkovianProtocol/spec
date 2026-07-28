# Event provenance and tamper-evidence for CDEvents

Status: informational companion document. This guidance is optional and additive; it
does not change the core CDEvents specification or any schema.

## Introduction

A CDEvent describes something that happened in a delivery pipeline: an artifact was
published, a build finished, a change was merged. Downstream systems increasingly
make decisions on these events (promotion gates, policy checks, audit trails), so two
separate questions arise:

1. Authenticity and integrity. Who emitted this event, and has its payload been
   altered in transit or at rest?
2. Existence over time. Did this event actually exist by some point in time, and can
   that be checked later without trusting the emitter's clock, or its continued
   custody of a signing key?

These are different properties and they need different mechanisms. A signature answers
question 1. It does not answer question 2: a signature proves who and whether-tampered,
but not when the event existed, and a holder of the signing key can re-sign a
back-dated or quietly reissued event at any time. Question 2 needs a commitment to the
event that is fixed against an external timeline.

This document describes both, as optional, additive guidance. Nothing here changes the
core CDEvents schema. Part 1 covers signing a CDEvent with a
[DSSE](https://github.com/secure-systems-lab/dsse) envelope. Part 2 covers an optional
commitment to the event's canonical hash, anchored to an external timeline. Part 2 is
strictly opt-in and deliberately anchor-agnostic: the commitment is just the event
digest, and where it is anchored is an implementation choice.

## Background: how a CDEvent is carried

Per the CDEvents [CloudEvents binding](https://github.com/cdevents/spec/blob/main/cloudevents-binding.md),
a CDEvent is transported as the `data` of a
[CloudEvent](https://github.com/cloudevents/spec) with `datacontenttype`
`application/json`, and the CloudEvents `id`, `source`, `type`, `subject` and `time`
attributes are mapped from the CDEvent's context. The guidance below can be applied at
either layer. Signing and hashing the CDEvent document (its `context` plus `subject`,
the object defined by the CDEvents schema) keeps provenance tied to the event itself and
independent of the transport, which is the approach used in the worked example.

## Part 1: authenticity and integrity with DSSE

[DSSE](https://github.com/secure-systems-lab/dsse) (Dead Simple Signing Envelope) is the
signing envelope used by in-toto and SLSA attestations. It wraps an arbitrary payload
plus a payload-type string and one or more signatures, and it signs over a
Pre-Authentication Encoding (PAE) rather than the raw bytes, which removes
canonicalization ambiguity and cross-protocol confusion from the signature.

### The envelope

The DSSE JSON envelope ([envelope.md](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md))
is:

```json
{
  "payload": "<Base64(SERIALIZED_BODY)>",
  "payloadType": "<PAYLOAD_TYPE>",
  "signatures": [{ "keyid": "<KEYID>", "sig": "<Base64(SIGNATURE)>" }]
}
```

- `payload` is the Base64 (RFC 4648) encoding of the serialized CDEvent.
- `payloadType` is an opaque, case-sensitive string identifying how to interpret the
  payload. This guide uses `application/cdevents+json`. `payloadType` is authenticated,
  so a signature over a CDEvent cannot be replayed as a signature over a different
  document type.
- Each `signatures[].sig` is the Base64 signature. `keyid` is an optional,
  unauthenticated hint for key selection.

### What is signed: the PAE

DSSE signs the Pre-Authentication Encoding of the payload, defined in
[protocol.md](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md):

```
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
SP        = ASCII space (0x20)
LEN(s)    = ASCII decimal byte length of s, no leading zeros
"DSSEv1"  = ASCII bytes 44 53 53 45 76 31
```

A verifier reconstructs `PAE(payloadType, Base64Decode(payload))` and checks the
signature against a trusted public key. Per DSSE guidance, the verified bytes are used
as-is; they are not re-parsed or re-canonicalized before use.

### What DSSE proves, and what it does not

Proves:
- Authenticity. The event was signed by a holder of the private key for `keyid`.
- Integrity. Any change to the CDEvent payload, or to `payloadType`, invalidates the
  signature.

Does not prove:
- When the event existed. A signature carries no trustworthy time. Any `timestamp`
  inside the event is asserted by the emitter and can be set to any value.
- That the event was not reissued. A party holding the signing key can produce a fresh,
  validly-signed event with different content at any later time.

Note on CloudEvents: a message-level signature profile for CloudEvents itself is an open
discussion in the CloudEvents project
([cloudevents/spec#565](https://github.com/cloudevents/spec/issues/565)) rather than a
finished standard. Applying DSSE to the CDEvent document, as described here, does not
depend on that work and is compatible with signing at either the CDEvent or the
CloudEvents layer.

## Part 2: existence over time with an optional hash commitment

To answer "did this event exist by time T", commit to the event and fix that commitment
against a timeline that the emitter does not control. This is independent of, and
complementary to, the DSSE signature.

### The commitment

1. Canonicalize the CDEvent with [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
   (JSON Canonicalization Scheme, JCS). JCS gives a single, deterministic byte
   serialization for a JSON value, so any party recomputes the same bytes from the same
   event.
2. Hash the canonical bytes with SHA-256. This digest is the commitment. In the worked
   example it is labeled `RFC8785-JCS+SHA-256`.
3. Record the digest on an external timeline so that its existence-by-time-T can be
   checked later.

Step 3 is where the anchor lives, and this guide is deliberately anchor-agnostic. A
digest can be fixed against a timeline in several ways, for example:

- an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) trusted timestamp from a Time
  Stamping Authority,
- an append-only transparency log (for example a Merkle-tree log in the style of
  RFC 9162),
- inclusion in a public blockchain transaction.

Which anchor to use is an operational and threat-model choice. The only thing CDEvents
tooling needs to agree on is the commitment itself: the canonicalization
(RFC 8785) and the hash (SHA-256). Everything about the anchor is out of scope for this
document and MUST NOT be assumed by consumers.

### What the commitment adds beyond DSSE

- Existence proof. Given the event, anyone can recompute the digest and check it against
  the anchor's record, establishing that the event existed by the time the anchor was
  written.
- Independence from key custody. The check does not require the emitter's signing key or
  its clock. It survives key loss, key rotation, and emitter compromise after the anchor
  time.
- Reissue detection. Because the digest is bound to a point on the timeline, a later
  re-signed variant of the event produces a different digest with no earlier anchor.

The commitment does not prove authorship. Only the DSSE signature does. The two are
designed to be used together.

## When to use which

| Requirement | DSSE signature (Part 1) | Hash commitment + anchor (Part 2) |
| --- | --- | --- |
| Prove who emitted the event | Yes | No |
| Detect payload tampering | Yes | Yes (digest mismatch) |
| Prove the event existed by time T | No | Yes |
| Verifiable without the emitter's key | No | Yes |
| Verifiable without trusting the emitter's clock | No | Yes |
| Detect a later re-signed / back-dated reissue | No | Yes |
| Extra infrastructure required | A key and key distribution | An external timeline / anchor |
| Status in this guidance | Recommended baseline | Optional, opt-in |

Baseline: sign CDEvents with DSSE. Add a Part 2 commitment when downstream decisions
need existence-over-time or must survive emitter key compromise, for example regulated
audit trails or long-lived provenance.

## Worked example

A runnable end-to-end example accompanies this guide at
[MarkovianProtocol/cdevents-provenance](https://github.com/MarkovianProtocol/cdevents-provenance).
It is kept outside this repository so that CDEvents takes no dependency on it.

The example uses real libraries rather than stubs: `rfc8785` for JCS canonicalization,
`cryptography` for Ed25519, and `jsonschema` to validate the sample event against the
published CDEvents artifact-published schema. It contains a valid
`dev.cdevents.artifact.published.0.3.0` event (CDEvents v0.5.1), its JCS canonical
serialization, the Part 2 commitment, a DSSE envelope over the canonical bytes, and a
tampered variant of each. Its verifier shows the genuine artifacts passing both checks
(the signature verifies, and SHA-256 of the signed payload equals the committed hash)
and the tampered artifacts failing both.

The example is illustrative. It uses one possible anchor mechanism; as stated in Part 2,
the choice of anchor is out of scope for this guidance.

## References

- DSSE envelope format: secure-systems-lab/dsse, `envelope.md`.
  https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
- DSSE protocol and PAE: secure-systems-lab/dsse, `protocol.md`.
  https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- RFC 8785, JSON Canonicalization Scheme (JCS). https://www.rfc-editor.org/rfc/rfc8785
- RFC 4648, Base64 (used by DSSE `payload`/`sig`). https://www.rfc-editor.org/rfc/rfc4648
- RFC 3161, Time-Stamp Protocol (one possible anchor for Part 2).
  https://www.rfc-editor.org/rfc/rfc3161
- RFC 9162, Certificate Transparency v2 (transparency-log style anchor for Part 2).
  https://www.rfc-editor.org/rfc/rfc9162
- CDEvents CloudEvents binding.
  https://github.com/cdevents/spec/blob/main/cloudevents-binding.md
- CloudEvents specification. https://github.com/cloudevents/spec
- CloudEvents message-level signature discussion (open).
  https://github.com/cloudevents/spec/issues/565