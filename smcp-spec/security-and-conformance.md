# SMCP Security and Conformance Requirements

Status: normative release criteria for SMCP 1.0 draft `0.1.0-draft.1`.

This document turns the core security model into observable tests. “Accept”
means the record advances the specified state and, where applicable, creates
exactly one expected effect. “Reject” means no effect, capability, consent use,
quota consumption, trust change, or success receipt occurs; the specified safe
error and audit event are produced where a secure response is possible.

## 1. Conformance Harness Contract

The System Under Test (SUT) exposes only normal SMCP endpoints plus an isolated
test-control plane capable of:

- provisioning deterministic test trust bundles, credentials, clocks, entropy
  streams, policy bundles, manifests, resources, quotas, and replay stores;
- observing resource state, operation journal, consent/quota counters, outbound
  network attempts, sandbox policy, and audit commitments;
- forcing a crash at named durability boundaries and restarting with retained or
  intentionally lost storage;
- advancing the trusted clock and publishing signed epoch/status changes; and
- retrieving protected diagnostics without returning them to the protocol peer.

The control plane is absent from production builds. Test private keys are
published with vectors and are cryptographically rejected by production trust
bundles. Each test starts with a declared complete state and has a hard deadline.

## 2. Reference Test Identities and Time

Canonical vector time is `2000000000000` epoch milliseconds. Clock skew is zero
unless the test states otherwise. The corpus defines principals:

```text
spiffe://alpha.example/agent/alice
spiffe://alpha.example/service/capability
spiffe://alpha.example/service/consent
spiffe://alpha.example/service/audit
spiffe://beta.example/tool/files
https://id.alpha.example/subjects/human-7f3a
urn:smcp:principal:gateway-mcp-test
```

Each corpus release contains deterministic P-256 and Ed25519 test keys, X.509
SVID chains, trust bundles, COSE objects, WebAuthn assertions, EAT evidence,
TUF metadata, Sigstore bundle, in-toto statement, and transparency tree. Private
keys exist solely to reproduce vectors. Real deployments never import them.

## 3. Normative Assertions

### 3.1 Encoding and record security

| ID | Stimulus | Expected result |
|---|---|---|
| `ENC-001` | Encode every message with boundary-valued fields. | Bytes exactly match the canonical corpus; decode/re-encode is identical. |
| `ENC-002` | Reverse map-key order while retaining a valid signature over those non-deterministic bytes. | Reject `MALFORMED_RECORD`; deterministic form is mandatory even when signature verifies. |
| `ENC-003` | Duplicate each envelope/body key one at a time, with same and differing values. | Reject `DUPLICATE_KEY` before semantic dispatch. |
| `ENC-004` | Use indefinite lengths, non-shortest integers/lengths, invalid UTF-8, forbidden float/NaN, self-described tag, trailing bytes. | Reject, allocate no object proportional to claimed unbounded size. |
| `ENC-005` | Nest arrays/maps at limits 15, 16, and 17. | Accept valid depths through 16; reject 17 with `LIMIT_EXCEEDED`. |
| `ENC-006` | Announce length 0, max, max+1, and truncate every byte position. | Only valid complete object at or below max is parsed. |
| `SIG-001` | One valid record of every message type under S1 and S2. | Verify type/schema and dispatch only in legal state. |
| `SIG-002` | Flip every protected field, envelope field, body byte, signature byte, AAD binding, and transcript hash independently. | Reject with no effect; protected/envelope duplicates must match. |
| `SIG-003` | Put interpretation data in unprotected COSE map. | Reject `MALFORMED_RECORD`. |
| `SIG-004` | Use unknown/forbidden algorithm, wrong curve, invalid point, malformed ECDSA/Ed25519 signature, `alg=none`. | Reject without algorithm fallback or timing-sensitive detail. |
| `SIG-005` | Valid signature but wrong exact audience, display-name-equivalent issuer, or alternate URI spelling. | Reject `AUDIENCE_MISMATCH` or authentication failure. |
| `SIG-006` | Transplant a signed record to another TLS channel/session/relay mode. | Reject `CHANNEL_BINDING_FAILED` or session mismatch. |

### 3.2 Negotiation, authentication, and sessions

| ID | Stimulus | Expected result |
|---|---|---|
| `NEG-001` | All pairwise intersections of versions/suites/transports/encodings/compression. | Server selects exactly one offered locally allowed value or returns `NEGOTIATION_NO_COMMON`. |
| `NEG-002` | Strip the highest offer, alter order, inject selection, change ALPN, minimum, max-supported, limits, or critical extension. | FINISH/transcript fails as `NEGOTIATION_DOWNGRADE`; connection closes, no fallback. |
| `NEG-003` | Unknown critical vs unknown noncritical informational extension. | Critical rejects; negotiated noncritical metadata is ignored without changing behavior. |
| `NEG-004` | Request zstd for secret or mixed-origin body, dynamic secret dictionary, decompression ratio/size over bound. | `COMPRESSION_FORBIDDEN` or `LIMIT_EXCEEDED`, no partial delivery. |
| `AUT-001` | Valid SPIFFE, WebPKI-app, OIDC-session, Trust-Bundle-key profiles. | Normalize to corpus identity facts and bind fresh session key. |
| `AUT-002` | Wrong issuer/audience/key use/SAN, expired/not-yet-valid/status-stale/suspended credential, unknown trust domain. | Uniform `AUTHENTICATION_FAILED` or safe status code; no principal enumeration. |
| `AUT-003` | Reuse holder proof with changed role, key, nonce, credential, transcript, or channel. | Reject proof. |
| `AUT-004` | Stale/wrong-nonce EAT, altered reference/appraisal policy, unknown critical claim. | Reject or require fresh attestation; never infer a grant. |
| `SES-001` | Application record before both FINISH messages. | `WRONG_STATE`, no dispatch. |
| `SES-002` | Rekey at activation sequence with 0, 1, 32, and 33-record overlaps. | Correct key accepted only in allowed window; old key erased/rejected afterward. |
| `SES-003` | Reauth weakens assurance below an active operation requirement. | Operation pauses/cancels; weak result does not replace required claim. |
| `SES-004` | CLOSE during requests, prepared effects, streams, and commit. | No new operations; each existing item reaches profile-defined terminal/reconciliation state and receipts verify. |

### 3.3 Replay and freshness

| ID | Stimulus | Expected result |
|---|---|---|
| `RPL-001` | Replay each accepted record in same session. | `REPLAY_DETECTED`; no second state change. |
| `RPL-002` | Repeat message ID under different sequence; sequence under different ID; reorder/gap. | Duplicate rejected; ordered gap follows transport resync/close rule. |
| `RPL-003` | Reuse nonce for authentication, consent, commit, risk, revocation, and audit proof. | Context replay rejected. |
| `RPL-004` | Replay an unexpired record after session reconnect or under new session key. | Session/channel binding rejection. |
| `RPL-005` | Reboot relay recipient with durable replay store intact. | Redelivery rejected; terminal acknowledgement reproduced. |
| `RPL-006` | Deliberately lose relay replay state. | Mutations block until replay/key epoch rotates; system never assumes empty state is safe. |
| `RPL-007` | Send mutation/capability/consent/trust/audit admin in TLS/QUIC 0-RTT. | Server rejects before effect regardless of application idempotency key. |

### 3.4 Capability, policy, risk, and consent

| ID | Stimulus | Expected result |
|---|---|---|
| `CAP-001` | Valid root and chains at depth 0, 4, 8, 9. | Profile depth accepted; above absolute 8 rejected. |
| `CAP-002` | Widen child action, resource, argument, destination, data class, time, quota, purpose, effect, attestation, result, audience, or delegate selector one at a time. | `DELEGATION_AMPLIFICATION`. |
| `CAP-003` | Child constraint logically narrows but verifier cannot prove registered implication. | Reject, demonstrating fail-closed relation. |
| `CAP-004` | Present token from wrong holder/session key or forward valid token. | PoP failure; target does not reveal scope details. |
| `CAP-005` | Revoke leaf, ancestor, subject, key, and issuer epoch while calls/preparations/subscriptions exist. | All affected authority stops within freshness bound; uncommitted state cancels. |
| `CAP-006` | Two concurrent requests consume last quota unit. | Exactly one succeeds/reserves; counter never underflows. |
| `POL-001` | No matching permit; matching permit; matching permit+forbid; PDP timeout/error/unknown fact. | Deny, permit, deny, indeterminate-as-deny respectively. |
| `POL-002` | Return signed decision for altered input or old policy/security epoch. | PEP rejects digest/epoch and reevaluates. |
| `POL-003` | Policy attempts network/time/random/model/plugin call or unregistered function. | Bundle validation/evaluation fails closed. |
| `RSK-001` | Risk engine returns observe/restrict/require/block. | Observe grants nothing; restrictions/controls enforced; block denies. |
| `RSK-002` | Omit high-impact requested factor, change input digest, expire assessment, or return unknown outcome. | Unknown explicit and policy handles conservatively; mismatched/expired/unknown result rejected. |
| `CNS-001` | Valid one-use consent for exact prepared digest, then two concurrent commits. | Exactly one consumes consent; other gets `CONSENT_INVALID` or identical already-committed result if same operation. |
| `CNS-002` | Swap actor, recipient, resource, version, action, args, schema, manifest, effect, destination, purpose, display, expiry, or capability digest after approval. | Consent invalid; no commit. |
| `CNS-003` | Invalid WebAuthn origin/RP/challenge/signature/UV/counter-policy input. | Receipt not minted. |
| `CNS-004` | Denial/timeout followed by automatic repeat or representation as approval. | No approval; retry policy blocks consent fatigue behavior. |
| `CNS-005` | Revoke approval before commit and race revocation with commit. | Serialized security epoch gives one authoritative outcome; never unlogged double outcome. |

### 3.5 Manifest, supply chain, and registry

| ID | Stimulus | Expected result |
|---|---|---|
| `MAN-001` | Valid manifest/artifact/schema/provenance/SBOM/TUF/Sigstore/in-toto/log chain. | Exact artifact is eligible only for declared permissions/effects. |
| `MAN-002` | Change each manifest field or artifact byte without publisher re-signing. | Signature/digest failure. |
| `MAN-003` | Validly sign manifest whose provenance subject/artifact/schema/effect digest differs. | `MANIFEST_INVALID` or `ARTIFACT_MISMATCH`. |
| `MAN-004` | TUF rollback, freeze, mix-and-match, wrong delegated path, expired timestamp/snapshot, below-threshold root. | Reject update/object; cached version used only until its own validity ends. |
| `MAN-005` | Tool requests undeclared file/network/cloud/secret/process permission. | Sandbox/PEP denies without “allow anyway”; audit violation. |
| `MAN-006` | Signed malicious release or high reputation with no capability. | No authorization; reputation cannot grant. |
| `REG-001` | Replace bytes under digest/version; decrease snapshot/epoch; delete history. | Reject/detect; deletion is signed tombstone only. |
| `REG-002` | Split-view log/registry with two tree heads. | Honest witness/gossip detects inconsistency; affected high-risk use blocks. |
| `REG-003` | Query unauthorized vs nonexistent sensitive tool/resource. | Indistinguishable safe response envelope/timing bucket per profile. |

### 3.6 Operations, streams, and audit

| ID | Stimulus | Expected result |
|---|---|---|
| `OPR-001` | One-phase request declared mutating, externally communicating, non-idempotent, or authority-changing. | Reject; requires prepare/commit. |
| `OPR-002` | Prepare, change resource version/policy/revocation/manifest/risk/consent/security epoch, then commit. | Commit fails or re-prepares; stale decision never executes. |
| `OPR-003` | Change any prepared/commit digest, nonce, reservation, evidence, deadline. | `COMMIT_MISMATCH`/expiry, no effect. |
| `OPR-004` | Send 100 concurrent identical commits. | Exactly one effect; 100 responses converge on identical terminal receipt. |
| `OPR-005` | Reuse idempotency key with different body. | Permanent mismatch, audit security event. |
| `OPR-006` | Crash before intent durability, after intent, after reservation, before effect, after effect before response, during audit outbox. | Recovery yields zero or one effect, stable journal/receipt, never blind repeat. |
| `OPR-007` | External outcome unavailable. | `IN_DOUBT`; caller status-queries and never automatically repeats. |
| `OPR-008` | Compensate successful irreversible/partly reversible effect. | Separate capability/policy/consent/audit operation required. |
| `STR-001` | Exact credit, credit+1, gap, overlap, duplicate, reorder, reused stream ID, post-close data. | Only exact valid stream accepted; violation closes stream and never releases unverified bytes to effectful sink. |
| `STR-002` | Correct chunks with wrong final digest/size/count. | `STREAM_INTEGRITY`; partial result not treated as complete. |
| `STR-003` | Revoke authority/change classification during subscription. | Reauthorization closes/narrows before further events. |
| `AUD-001` | Side effect while required audit append/receipt unavailable. | `AUDIT_UNAVAILABLE`, zero effect. |
| `AUD-002` | Remove/reorder/change/re-sign event; fork emitter chain. | Hash-chain/proof verification fails or divergence alerts. |
| `AUD-003` | Search default audit/metrics/traces/errors for corpus secrets, tokens, prompts, args, WebAuthn data, raw PII. | No occurrence; only declared hashes/classes/opaque refs. |
| `AUD-004` | Inclusion promise exceeds merge deadline or proof is inconsistent. | Alert and block profile-required operations until resolved. |

### 3.7 Resource exhaustion and transport

| ID | Stimulus | Expected result |
|---|---|---|
| `DOS-001` | Slow length/body sender, handshake flood, invalid-signature flood, auth retry flood. | Per-stage deadlines/quotas/cookies bound connections, CPU and memory; valid principals retain reserved capacity. |
| `DOS-002` | Stream/event without credit, queue consumer stall, cancellation race. | Bounded buffers; sender blocked/rejected; terminal state consistent. |
| `DOS-003` | zstd high ratio, huge declared result/blob, recursive manifest/proof chain. | Declared hard bounds enforced before allocation/decompression/dereference. |
| `TRN-001` | TLS 1.2/plaintext/wrong ALPN/no client application auth/invalid endpoint identity. | Connection cannot enter `CHANNEL_SECURE`. |
| `TRN-002` | QUIC connection migration changes network policy fact. | Policy re-evaluates; forbidden migration closes or pauses sensitive operations. |
| `TRN-003` | Local socket ACL/OS peer differs from authenticated principal policy. | Authentication/authorization fails; OS identity is evidence, not replacement. |
| `TRN-004` | Relay reads or changes inner body/routing audience/replays after acknowledgement. | HPKE confidentiality, inner signature failure, or replay rejection; metadata leakage remains documented. |

## 4. Formal Model Requirements

The reference release includes three complementary models because no single
formalism covers state, symbolic cryptography, and implementation parsing.

### 4.1 TLA+ state model

Model principals, sessions, security epochs, capability DAGs, resources,
preparations, consent/quota counters, journals, effects, audit outboxes,
revocations, crashes, and message reorder/duplication. Check at minimum:

```text
AuthorizationSafety ==
  [] (EffectOccurred => RecordValid /\ CapabilityPermits /\ PolicyPermits
                       /\ RiskSafe /\ ObligationsMet /\ FreshEpochs)

AtMostOnce ==
  [] (Cardinality(EffectsFor(idempotency_key)) <= 1)

ConsentAtMostUses ==
  [] (Consumed(receipt) <= MaxUses(receipt))

DelegationMonotonic ==
  [] (Child(parent) => Authority(child) \subseteq Authority(parent))

NoStaleCommit ==
  [] (CommitAccepted => Prepared.security_epoch = CurrentSecurityEpoch)

AuditBeforeEffect ==
  [] (EffectOccurred => IntentDurableBeforeEffect)
```

Run exhaustive finite instances with at least three principals, two concurrent
callers, depth-two delegation, two resources, crash/restart, revocation and
consent races. Liveness checks cover completion or explicit `IN_DOUBT` under fair
delivery and available dependencies; availability is never allowed to violate
safety.

### 4.2 Tamarin/ProVerif symbolic model

Model TLS exporter as an authenticated channel-binding secret per RFC security
assumptions, long-term credential compromise at chosen times, ephemeral session
keys, COSE signatures, transcript, capabilities, delegation, consent, and HPKE
relay. Prove or find counterexamples for mutual transcript agreement, record
origin/audience agreement, session separation, replay resistance, holder proof,
authorization correspondence, delegation ancestry, consent-effect agreement,
forward secrecy under post-session long-term compromise (as supplied by TLS),
and compromise/revocation scope. Explicitly state which properties fail under
endpoint or issuer compromise; do not hide them as assumptions.

### 4.3 Parser/canonicalization model

Property/differential tests establish that every accepted security object maps
to exactly one deterministic byte string and semantic tree; no two accepted byte
strings represent one signed logical object. Verification uses the received
exact bytes, and parsers agree on integer sign/range, duplicate keys, tags,
Unicode, nesting and end-of-input.

## 5. Fuzz Campaign Release Gates

For each release candidate:

- every pure parser target runs at least 10 CPU-hours with no new path for the
  final 60 minutes and no unresolved crash/hang/limit violation;
- stateful/network targets run at least 24 aggregate CPU-hours including crash
  scheduling and loss/reorder/duplicate faults;
- differential corpus covers all messages and long-lived objects under at least
  three independently maintained CBOR implementations and two COSE stacks;
- concurrency testing explores at least 10,000 randomized schedules for every
  consent/quota/prepare/commit/revocation critical section;
- all historical security findings remain in the regression corpus; and
- sanitizer runs have zero untriaged findings.

These durations are minimum release gates, not claims of completeness. Coverage
plateau is not evidence that a target is safe; grammar-aware seeds and manual
adversarial cases remain required.

## 6. Interoperability Matrix and Result Format

Every pairwise run emits a signed deterministic report:

```text
protocol/profile versions
implementation names and immutable build/provenance digests
OS, architecture, crypto/TLS/QUIC/policy providers and modes
trust/vector/conformance-suite digests
assertion ID -> pass/fail/not-applicable + evidence digest
semantic transcript hash and terminal state
side-effect, consent, quota, journal and audit counters
start/end time and runner principal/signature
```

`not-applicable` is valid only when the claimed profile excludes the feature.
Skipped or flaky results fail certification. Tests execute both implementation
directions and include a third-party proxy/relay where the profile supports it.
The matrix has at least Windows, Linux and macOS clients; x86-64 and ARM64;
different TLS/QUIC providers; S1 and S2; direct/local/H3 and relay where claimed;
SPIFFE and human profiles; two PDPs; two registries; and two independent logs.

## 7. Threat-to-Assertion Traceability

| Threat | Primary assertions | Residual-risk exercise |
|---|---|---|
| Prompt/indirect injection | `POL-001..003`, `CNS-002`, `MAN-005`, `OPR-001` | Authorized user approves semantically harmful but accurately shown action; document that protocol cannot guarantee judgment. |
| Tool/manifest poisoning | `MAN-001..006`, `REG-001..003` | Correctly signed malicious publisher release; verify sandbox/blast radius and revocation. |
| MITM/tampering/confusion | `SIG-002..006`, `NEG-002`, `TRN-001..004` | Compromised endpoint key; verify audit/revocation rather than impossible prevention claim. |
| Replay/token theft/session hijack | `RPL-*`, `CAP-004..006`, `SES-*` | Live holder process compromise; verify narrow authority/expiry/monitoring. |
| Privilege/confused deputy/cross-agent | `CAP-002..005`, `POL-*`, `CNS-002`, `OPR-002` | Colluding authorized agents; exercise information-flow/egress policy. |
| Supply chain | `MAN-*`, `REG-*` | Threshold/root/build compromise recovery drill. |
| Compromised host/user/model/tool | `AUT-004`, `RSK-*`, `CNS-*`, `MAN-005`, `OPR-*`, `AUD-*` | Run compromise-at-time symbolic cases and incident playbook. |
| DoS/resource exhaustion | `ENC-005..006`, `DOS-*`, `STR-*` | Capacity exhaustion beyond provisioned budget; measure graceful degradation. |
| Race/TOCTOU | `CAP-006`, `CNS-001/005`, `OPR-002..007` | Non-atomic legacy dependency; high-assurance rejection required. |
| Downgrade | `NEG-*`, `TRN-001`, migration assertions | Operator intentionally configures legacy endpoint; assurance label and policy remain explicit. |
| Audit deletion/equivocation | `AUD-*`, `REG-002` | Log plus all witnesses collude; record residual organizational trust. |

## 8. MCP Gateway Conformance

The migration gateway is tested with MCP stdio and HTTP transports, malformed
JSON-RPC, OAuth discovery, redirect/SSRF inputs, tool list changes, schema
changes, server-name collision, session-ID confusion, notifications, and
disconnect/retry. It MUST:

1. authenticate the legacy side as strongly as that environment permits;
2. sign only as its gateway principal;
3. set source protocol/version, original digest, mapping-policy digest,
   assurance limit, synthesized-field list, and `origin_signature=false`;
4. exchange—not forward—OAuth bearer tokens into exact PoP capabilities;
5. mark generated manifests/provenance unverified and deny undeclared effects;
6. apply prepare/commit to unknown or effectful calls;
7. prevent redirect, DNS-rebinding, private-address, credential-forwarding and
   cross-client session attacks;
8. produce gateway audit evidence without claiming legacy audit immutability;
9. expose fallback only at a separately configured address/profile; and
10. never automatically downgrade after native SMCP negotiation failure.

Passing gateway tests is a `MIG` capability statement, not SMCP Core conformance
for the legacy endpoint.
