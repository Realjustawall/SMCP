# SMCP Initial Registries

Status: normative for SMCP 1.0 draft `0.1.0-draft.1`.

These tables prevent private strings from acquiring accidental security meaning.
Until an IANA registry exists, the SMCP project maintains them under public
Specification Required review. A registration includes a stable specification,
security/privacy analysis, safe unknown behavior, deterministic schema, test
vectors, change controller, and contact. Cryptographic entries additionally
require allocation or stable specification in the governing COSE/TLS/HPKE
registry. “First come” and vendor popularity are not sufficient.

Updates cannot redefine an allocated value. A harmful value is marked
deprecated or prohibited with a signed effective date; its old semantics remain
available for historical verification. Ranges `0xF000–0xFFFF` and URIs rooted in
an organization-controlled HTTPS/URN namespace are private use and forbidden in
standard compliance profiles unless explicitly named.

## 1. Message Types

| Value | Name | Direction/state |
|---:|---|---|
| 1 | `CLIENT_HELLO` | Initiator, first application record |
| 2 | `SERVER_HELLO` | Responder, negotiating |
| 3 | `AUTHENTICATE` | Both, authenticating/reauthenticating |
| 4 | `AUTH_RESULT` | Both, authenticating/reauthenticating |
| 5 | `FINISH` | Both, confirming |
| 6 | `REAUTH` | Both, established |
| 7 | `REKEY` | Both, established/rekeying |
| 8 | `CLOSE` | Both, established/draining |
| 9 | `CLOSE_ACK` | Both, draining |
| 16 | `DISCOVER` | Client, established |
| 17 | `DISCOVERY_RESULT` | Service/registry, established |
| 32 | `CAP_REQUEST` | Holder, established |
| 33 | `CAP_GRANT` | Issuer/STS, established |
| 34 | `CAP_DELEGATE` | Delegator, established |
| 35 | `CAP_REVOKE` | Authorized administrator/issuer |
| 36 | `REVOCATION_QUERY` | Verifier, established |
| 37 | `REVOCATION_STATUS` | Status authority, established |
| 48 | `CONSENT_REQUEST` | PEP/consent service, established |
| 49 | `CONSENT_RESPONSE` | Consent authority/service, established |
| 50 | `CONSENT_REVOKE` | Consent authority/service, established |
| 64 | `RISK_REQUEST` | PEP, established |
| 65 | `RISK_ASSESSMENT` | Risk engine, established |
| 80 | `OP_REQUEST` | Caller, established; safe one-phase reads only |
| 81 | `OP_PREPARE` | Caller, established |
| 82 | `OP_PREPARED` | Resource service, established |
| 83 | `OP_COMMIT` | Caller, established |
| 84 | `OP_RESULT` | Resource service, established |
| 85 | `OP_CANCEL` | Either operation party, established/draining |
| 86 | `OP_STATUS` | Query or authoritative result, established |
| 96 | `STREAM_OPEN` | Either, established |
| 97 | `STREAM_DATA` | Bound stream sender, established |
| 98 | `STREAM_CREDIT` | Bound stream receiver, established |
| 99 | `STREAM_CLOSE` | Either, established/draining |
| 112 | `SUBSCRIBE` | Subscriber, established |
| 113 | `EVENT` | Publisher, established |
| 114 | `UNSUBSCRIBE` | Either, established/draining |
| 128 | `MANIFEST_GET` | Client, established |
| 129 | `MANIFEST_RESULT` | Publisher/registry, established |
| 130 | `REGISTRY_QUERY` | Client, established |
| 131 | `REGISTRY_RESULT` | Registry, established |
| 144 | `AUDIT_SUBMIT` | Emitter, established |
| 145 | `AUDIT_RECEIPT` | Log, established |
| 146 | `AUDIT_PROOF_REQUEST` | Verifier, established |
| 147 | `AUDIT_PROOF` | Log/witness, established |
| 255 | `ERROR` | Either; state-safe only |

Values 0, 10–15, 18–31, 38–47, 51–63, 66–79, 87–95, 100–111,
115–127, 132–143, and 148–254 are reserved for standards action.

## 2. Algorithm Suites

| ID | Name | Record/objects | Hash | TLS/relay | Status |
|---:|---|---|---|---|---|
| 1 | `S1` | COSE ES256 (P-256 ECDSA) | SHA-256 | TLS 1.3 registered AEAD; HPKE DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM when relay used | REQUIRED to sign and verify in Core |
| 2 | `S2` | COSE EdDSA with Ed25519 | SHA-256 for object digests | TLS 1.3 registered AEAD; HPKE X25519/HKDF-SHA256/ChaCha20-Poly1305 when relay used | RECOMMENDED; REQUIRED to verify in Core |
| 3 | `S1-FIPS` | ES256 via approved provider/module | SHA-256 | approved TLS 1.3 and P-256/AES-GCM HPKE configuration | HIGH-ASSURANCE option where regulation requires |

Signature generation MUST use the selected suite; verification accepts only
locally allowed suites. ECDSA implementations require approved nonce generation,
strict signature encoding, curve/point validation, and rejection of invalid
keys. Ed25519 means the pure registered Ed25519 variant required by COSE EdDSA;
variants are not inferred. Cryptographic registry updates name exact standards
and test vectors.

## 3. Transport, Encoding, and Compression Profiles

| Kind | ID | Meaning |
|---|---|---|
| Transport | `urn:smcp:transport:tls13:1` | TLS 1.3 reliable stream, ALPN `smcp/1`, length framing |
| Transport | `urn:smcp:transport:h3:1` | QUIC v1/HTTP3 extended CONNECT SMCP session |
| Transport | `urn:smcp:transport:local:1` | ACL-protected local IPC plus TLS 1.3 and OS peer evidence |
| Transport | `urn:smcp:transport:relay-hpke:1` | Durable broker with inner signed HPKE records |
| Encoding | `urn:smcp:encoding:cbor-deterministic:1` | RFC 8949 deterministic CBOR and `smcp-v1.cddl` |
| Encoding | `urn:smcp:encoding:json-diagnostic:1` | Non-native I-JSON/JCS view carrying original COSE bytes |
| Compression | `urn:smcp:compression:none:1` | No body compression; required/default |
| Compression | `urn:smcp:compression:zstd-rfc8878:1` | Restricted per-origin, non-secret Zstandard profile |

No `http`, `tcp`, `stdio`, `websocket`, `gzip`, or arbitrary algorithm-name
value is registered. A gateway may use them on its legacy side while declaring
the assurance boundary.

## 4. Credential and Attestation Profiles

| ID | Subject | Required validation |
|---|---|---|
| `urn:smcp:credential:spiffe-x509-svid:1` | Workload/tool/agent service | SPIFFE X.509-SVID and Bundle, exact single SPIFFE URI SAN, key use, lifetime, federation |
| `urn:smcp:credential:webpki-app:1` | Internet service | RFC 5280/WebPKI endpoint plus separate SMCP application principal assertion and status |
| `urn:smcp:credential:oidc-session:1` | Human/federated service | Exact issuer/audience/nonce/auth time, code+PKCE upstream, short-lived SMCP session assertion |
| `urn:smcp:credential:trust-bundle-key:1` | Rooted organization/key principal | COSE key and key-purpose entry from active Trust Bundle |
| `urn:smcp:attestation:eat-rats:1` | Device/workload runtime | RFC 9334 role separation, RFC 9711 EAT, verifier nonce, signed appraisal and reference-policy digest |
| `urn:smcp:consent:webauthn:1` | Human consent authority | RP/origin/challenge/type/signature/UV and local authenticator counter/backup policy |

DID registrations are per method and absent from Core until their resolution,
update, deactivation, key-purpose, privacy, and trust policy passes review.

## 5. Core Actions and Effect Classes

### 5.1 Protocol actions

| Action URI | Meaning |
|---|---|
| `urn:smcp:action:discover` | Query authorized service/tool metadata |
| `urn:smcp:action:capability.request` | Request a new root/exchanged capability |
| `urn:smcp:action:capability.delegate` | Create an attenuated child capability |
| `urn:smcp:action:capability.revoke` | Revoke authority or advance an issuer epoch |
| `urn:smcp:action:consent.request` | Ask a named authority for exact-effect consent |
| `urn:smcp:action:risk.assess` | Request a restriction assessment |
| `urn:smcp:action:manifest.read` | Retrieve exact manifest/proof bytes |
| `urn:smcp:action:registry.query` | Query authorized registry objects |
| `urn:smcp:action:registry.publish` | Publish immutable signed registry object |
| `urn:smcp:action:audit.append` | Submit signed audit events |
| `urn:smcp:action:audit.proof` | Query inclusion/consistency evidence |
| `urn:smcp:action:operation.status` | Reconcile an existing operation only |

### 5.2 Common resource actions

`urn:smcp:action:fs.read`, `fs.list`, `fs.create`, `fs.write`, `fs.delete`,
`fs.execute`, `database.select`, `database.insert`, `database.update`,
`database.delete`, `browser.navigate`, `browser.read`, `browser.submit`,
`http.request`, `cloud.read`, `cloud.mutate`, `infra.plan`, `infra.apply`,
`message.send`, `financial.quote`, `financial.commit`, `identity.read`,
`identity.modify`, `secret.use`, and `code.execute` are initially registered.
Each resource profile must specify canonical naming, argument schema, exact
effect mapping, idempotency, prepare/commit support, and subset comparison.

Effect classes are `read`, `write`, `execute`, `external-communicate`,
`financial`, `identity`, `privilege`, `destructive`, and `authority-change`.
An operation declares every applicable class; classes are not mutually exclusive.
Unknown effect classes are critical and block execution.

## 6. Constraints

| ID | Value / subset relation |
|---|---|
| `urn:smcp:constraint:argument:1` | Typed Cedar/CEL-profile predicate; child predicate must be statically proven to imply parent. |
| `urn:smcp:constraint:data-class:1` | Finite allowed classification set; child subset. |
| `urn:smcp:constraint:destination:1` | Canonical exact origins/services; child subset, no wildcard in Core. |
| `urn:smcp:constraint:quota:1` | Map of named unsigned maxima; child values and total reservation no larger. |
| `urn:smcp:constraint:time-window:1` | Closed not-before/expiry intervals; child contained in parent. |
| `urn:smcp:constraint:network-zone:1` | Finite signed zone IDs; child subset. |
| `urn:smcp:constraint:purpose:1` | Exact purpose or finite set; child subset. |
| `urn:smcp:constraint:attestation:1` | Accepted appraisal policy/reference sets and max age; child same/stronger and no older. |
| `urn:smcp:constraint:effect:1` | Allowed effect classes, reversible flag, maximum cost; child subset/lower cost/stronger reversibility. |
| `urn:smcp:constraint:result:1` | Maximum bytes, classifications and destinations; child narrows each. |

If an implementation cannot prove the registered subset relation, delegation
fails with `DELEGATION_AMPLIFICATION`.

## 7. Obligations

| ID | Completion proof |
|---|---|
| `urn:smcp:obligation:consent:1` | Valid exact consent receipt, atomically consumed at commit |
| `urn:smcp:obligation:user-verification:1` | Registered WebAuthn/credential proof with required UV/assurance |
| `urn:smcp:obligation:dual-control:1` | Threshold independent consent receipts over one digest |
| `urn:smcp:obligation:attestation:1` | Fresh signed appraisal matching policy/reference digest |
| `urn:smcp:obligation:sandbox:1` | Runtime evidence/PEP fact for named sandbox policy |
| `urn:smcp:obligation:network-isolation:1` | PEP-enforced egress policy digest and epoch |
| `urn:smcp:obligation:redaction:1` | Deterministic transform digest and output classification |
| `urn:smcp:obligation:audit-before-effect:1` | Durable audit receipt/inclusion promise for intent |
| `urn:smcp:obligation:witness:1` | Required independent witness signatures/checkpoint |
| `urn:smcp:obligation:rate-quota:1` | Atomic reservation ID and remaining quota proof |
| `urn:smcp:obligation:dry-run:1` | Signed plan/result digest bound into preparation |
| `urn:smcp:obligation:reversible:1` | Verified rollback capability/window before commit |
| `urn:smcp:obligation:cooling-off:1` | Trusted-time interval since approval, with no material input change |

Unknown critical obligations deny. A noncritical obligation may describe
post-result metadata only and cannot gate or alter an effect.

## 8. Audit Event Types

Initial event IDs are:

- `session.channel`, `session.negotiation`, `session.authentication`,
  `session.reauthentication`, `session.rekey`, `session.close`;
- `identity.enroll`, `identity.rotate`, `identity.suspend`, `identity.revoke`,
  `trust.bundle`, `trust.federation`, `trust.recovery`;
- `capability.request`, `capability.issue`, `capability.delegate`,
  `capability.use`, `capability.exhaust`, `capability.revoke`;
- `policy.publish`, `policy.activate`, `authorization.decision`, `risk.assessment`;
- `consent.request`, `consent.approve`, `consent.deny`, `consent.consume`,
  `consent.revoke`;
- `manifest.publish`, `manifest.verify`, `manifest.revoke`, `artifact.execute`;
- `operation.intent`, `operation.prepare`, `operation.commit`,
  `operation.result`, `operation.cancel`, `operation.reconcile`;
- `stream.open`, `stream.close`, `subscription.open`, `subscription.close`;
- `registry.publish`, `registry.query`, `audit.submit`, `audit.include`,
  `audit.checkpoint`, `audit.access`, `audit.dispose`;
- `security.violation`, `security.break-glass`, and `security.incident`.

Event type never controls authorization. Unknown event types remain signed and
hash-chain verifiable but receive a generic privacy-safe display.

## 9. Compliance Profile IDs

The exact IDs are `urn:smcp:profile:core:1`, `web:1`, `workload:1`, `human:1`,
`supply-chain:1`, `local:1`, `relay:1`, `high-assurance:1`, `regulated:1`, and
`constrained:1`, each under the `urn:smcp:profile:` prefix and with the semantics
in core Section 26. Profile claims name all applicable IDs, not merely the most
restrictive-looking display label.

## 10. Error Facilities

| Facility | High 12-bit value | Scope |
|---|---:|---|
| Framing/schema | `0x001` | Decode, size, type and state |
| Record security | `0x002` | Signature, audience, time, replay, binding |
| Negotiation | `0x003` | Version, suite, extension, compression |
| Authentication | `0x004` | Identity credential/status/attestation |
| Capability | `0x005` | Authority, delegation, quota, revocation |
| Policy/risk | `0x006` | PDP, obligations, risk |
| Consent | `0x007` | Approval lifecycle and verification |
| Manifest/artifact | `0x008` | Tool and supply-chain trust |
| Operation | `0x009` | Prepare, commit, cancellation, reconciliation |
| Stream | `0x00A` | Credit, ordering and integrity |
| Evidence/services | `0x00B` | Revocation, registry, audit, transparency |
| Availability | `0x00C` | Rate and deadlines |
| Internal | `0xFFF` | Safe implementation failure |

The complete initial reason allocation is normative in core Section 25. New
errors state retry safety for non-idempotent operations and enumeration/privacy
behavior.
