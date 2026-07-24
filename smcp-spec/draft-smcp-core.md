# Secure Model Communication Protocol (SMCP) 1.0

## Status of This Memo

This document is an Internet-Draft-style pre-standard specification. It has not
been submitted to or approved by the IETF. It defines version `1.0` of the
protocol and identifies work that is intentionally assigned to later documents;
all security-critical behavior within its scope is specified here.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in BCP 14
(RFC 2119 and RFC 8174) when, and only when, they appear in all capitals.

## Abstract

The Secure Model Communication Protocol (SMCP) is a transport-independent,
zero-trust application protocol for humans, AI agents, tools, services, APIs,
data stores, browsers, cloud systems, and infrastructure. SMCP makes identity,
message authentication, authorization, proof-of-possession capabilities,
human consent, software provenance, replay defense, and accountable audit
mandatory protocol properties. Transport confidentiality remains mandatory,
but it is not treated as a substitute for application security.

SMCP uses TLS 1.3 or QUIC for network channels; deterministic CBOR and COSE for
the wire object; CWT-style proof-of-possession capabilities; workload,
federated, and human identity profiles; Cedar authorization semantics with an
AuthZEN-compatible decision API; WebAuthn for high-assurance human approval;
RATS/EAT for attestation; and TUF, Sigstore, and in-toto for supply-chain trust.
It invents no cryptographic primitive.

---

## 1. Project Vision

SMCP exists because secure transport and an RPC envelope do not, by themselves,
answer the questions that matter when a probabilistic agent can cause durable
effects: *which cryptographic principal asked, under which delegated authority,
for exactly what effect, on which resource version, with whose consent, and
where is the verifiable record?*

The protocol's goal is a common security plane for:

- human-to-agent intention and consent;
- agent-to-agent delegation and provenance;
- agent-to-tool invocation;
- service, API, database, filesystem, browser, cloud, and infrastructure access;
- offline or brokered delivery without converting authority into bearer data.

SMCP is not “MCP with encryption.” HTTPS already encrypts MCP over HTTP. SMCP
defines the missing end-to-end application invariants: named principals,
signed records, capability-bound operations, effect-aware consent, signed tool
manifests, transactional execution, and transparent audit. A compatibility
gateway can expose an MCP system to SMCP, but the gateway is an explicit trust
termination point and cannot claim end-to-end SMCP properties.

### 1.1 Success criteria

An SMCP deployment succeeds when two conformant implementations with no shared
code can:

1. establish a mutually authenticated, downgrade-resistant session;
2. identify the human, agent instance, workload, tool, and publisher roles that
   participate in an operation;
3. make the same authorization decision from the same signed inputs;
4. reject replay, mutation, privilege amplification, and stale consent;
5. verify tool and update provenance before execution;
6. produce independently verifiable, privacy-preserving audit evidence; and
7. recover from key, host, tool, or trust-root compromise without global reset.

### 1.2 Decision record

| Item | Specification |
|---|---|
| Problem | Existing RPC protocols expose functions but do not bind identity, authority, intent, effect, and evidence into every operation. |
| Threat | A compromised model, stolen token, poisoned tool, or confused deputy can turn syntactically valid RPC into unauthorized effects. |
| Design | Make the secure application record, least-privilege capability, policy decision, consent obligation, and audit commitment part of the protocol. |
| Alternatives | Transport-only security; optional security middleware; bearer OAuth scopes; vendor-specific agent policy. |
| Tradeoffs | More bytes, cryptographic work, lifecycle services, and explicit failure modes in exchange for portable enforcement. |
| Advantages | Security properties survive proxies and transports; authorization inputs are interoperable; incidents are attributable. |
| Disadvantages | Anonymous use is excluded; legacy integration requires a gateway; deployment needs identity and audit infrastructure. |
| Security analysis | Mandatory checks remove insecure “optional mode” branches; they cannot protect a host that controls keys and enforcement code, so attestation, isolation, revocation, and blast-radius limits remain required. |
| Performance | Session keys and reference capabilities keep steady-state verification bounded; preparation adds a round trip only for side effects. |
| Compatibility | MCP/HTTP/gRPC systems can sit behind explicit adapters; unsigned legacy messages never become native SMCP messages. |
| Extensibility | Versioned registries and critical extensions allow evolution without weakening core invariants. |

## 2. Architecture Overview

SMCP separates seven layers. Each layer has a narrow contract; none may infer a
grant from content produced by a model.

| Layer | Name | Normative responsibility |
|---:|---|---|
| 0 | Trust and supply chain | Trust bundles, federation, update metadata, artifact provenance, attestation policy. |
| 1 | Confidential channel | TLS 1.3, QUIC, or an approved secure local profile; peer and endpoint protection. |
| 2 | Session | Algorithm/version negotiation, identity binding, transcript confirmation, reauthentication, rekey, replay window. |
| 3 | Secure record | COSE signature, deterministic CBOR, issuer/audience/time/session/sequence/type binding. |
| 4 | Authority | Capabilities, policy, delegation, risk restrictions, consent, quotas, revocation. |
| 5 | Operations | Discovery, manifests, prepare/commit calls, streams, subscriptions, cancellation, receipts. |
| 6 | Evidence | Signed audit events, hash chains, Merkle checkpoints, inclusion/consistency proofs, retention/export. |

The Policy Enforcement Point (PEP) sits at the resource owner. It consumes
verified facts from a Credential Verifier, Capability Verifier, Policy Decision
Point (PDP), Risk Engine, Consent Verifier, Manifest Verifier, and Revocation
Provider. The model is outside this trusted computing base. The final decision
is the intersection:

```text
ALLOW = channel_valid
    AND identity_valid
    AND record_valid_and_fresh
    AND capability_chain_permits
    AND policy_explicitly_permits
    AND risk_does_not_block
    AND all_obligations_satisfied
    AND consent_valid_if_required
    AND tool_and_resource_trust_valid
    AND quotas_available
```

An error, timeout, unknown critical field, indeterminate policy result, or stale
security input makes its term false.

### 2.1 Roles

- **Principal:** cryptographically named human, organization, workload, agent,
  tool instance, publisher, service, device, or auditor.
- **Initiator / Responder:** session roles; neither implies superior authority.
- **Resource owner:** principal whose policy controls a resource.
- **Issuer:** principal signing a credential, capability, manifest, or receipt.
- **Delegate:** principal receiving attenuated authority.
- **PEP / PDP:** enforcement and decision components, normally separate from the
  model and from untrusted tool code.
- **Consent authority:** human or organization allowed to approve a stated
  effect; it is never the requesting model itself.
- **Registry / transparency log / monitor:** discovery, evidence publication,
  and independent equivocation detection roles.

### 2.2 Minimal trusted computing base

The required TCB is: deterministic encoder/decoder, approved crypto provider,
private-key boundary, session and replay engine, credential/capability verifier,
PEP/PDP, consent verifier, manifest verifier, audit commit path, and trusted
clock or freshness service. Model inference, prompt construction, retrieval,
tool business logic, UI rendering, and registry search ranking are untrusted.

### 2.3 Protocol invariants

The following invariants are absolute for conformant Core implementations:

1. No anonymous session and no anonymous operation exist.
2. Every protocol record is a valid `COSE_Sign1` object; `alg=none` is invalid.
3. The signature binds protocol label, version, type, session, sequence,
   issuer, audience, expiry, body, and critical extensions.
4. Network plaintext transports are forbidden.
5. A transport-authenticated peer is not automatically authorized.
6. Bearer capabilities are forbidden; every capability binds a holder key.
7. Authorization is default-deny and is evaluated at the resource owner.
8. Delegation can only preserve or reduce authority, expiry, audience, quota,
   and delegation depth.
9. Content, prompts, retrieved text, model output, and tool output are data and
   cannot create identity, authority, policy, consent, or trust.
10. A side effect cannot execute without a fresh prepared reservation and a
    commit that binds its digest.
11. Consent binds the human, action, resource, normalized argument digest,
    declared effects, data classes, recipient, expiry, and usage count.
12. A risk engine may deny, narrow, sandbox, or require stronger proof; it may
    never grant authority absent policy and capability.
13. Unknown critical extensions, algorithms, or fields fail closed.
14. Negotiation is transcript-bound; silent fallback is forbidden.
15. Mutating operations and authority issuance are forbidden in TLS/QUIC 0-RTT.
16. Duplicate CBOR map keys, non-deterministic security objects, invalid UTF-8,
    and ambiguous numeric representations are rejected.
17. A tool may exercise only permissions declared in its signed manifest and
    independently granted by capability and policy.
18. Reputation never grants access; it is signed risk evidence only.
19. Revocation freshness is policy bounded; “status unavailable” is not “good.”
20. Every accepted or rejected record contributes its signed digest to a durable
    or checkpointed session audit accumulator; security decisions and attempted
    side effects additionally produce individually typed audit events.
21. Audit claims are tamper-evident, not magically immutable; external
    checkpoints and monitoring are required to detect log equivocation.
22. Secrets, raw credentials, capabilities, prompts, and personal content are
    not written to default audit records.
23. Identity rotation does not change principal identity; key compromise does
    not silently create a new principal.
24. The effective audience is exact; wildcard audiences are forbidden in Core.
25. Session and message identifiers are never reused under a signing key.
26. Authorization is re-evaluated after relevant policy, identity, capability,
    consent, manifest, risk, resource-version, or revocation changes.
27. Gateways declare which properties they terminate and never fabricate
    upstream signatures or attestation.
28. Extensions cannot override these invariants.

### 2.4 Comparison

HTTP and gRPC define interoperable requests but leave authorization and audit to
applications. HTTPS/TLS/QUIC strongly protect channels but do not define the
meaning or authority of an AI action. SSH binds a peer and channel but does not
model delegated tool effects. OAuth 2.0/OIDC provide authorization and identity
building blocks, commonly at HTTP endpoints, but do not make every agent record,
manifest, consent, and audit event one coherent protocol. SPIFFE provides strong
workload identity but not human intent or operation semantics. Kubernetes has
useful admission and RBAC patterns but remains platform-specific. MCP provides
excellent tool/context interoperability and security guidance; its core
JSON-RPC data model does not universally require signed application messages,
proof-of-possession capabilities, effect-bound consent, or verifiable audit.

## 3. Protocol Philosophy

SMCP applies these rules:

- **Authenticate facts, not prose.** Security input is typed and signed.
- **Authority travels as an attenuating capability, not ambient credentials.**
- **Policy lives beside the resource, not inside a probabilistic model.**
- **Intent precedes effect.** Preparation exposes the exact planned action to
  policy and a human before commit.
- **Evidence is first-class.** Decisions produce receipts and log commitments.
- **Secure defaults are protocol law.** Implementations have no insecure Core
  negotiation value.
- **Agility is bounded.** Registries can add reviewed algorithms and profiles;
  peers cannot negotiate unregistered arbitrary crypto.
- **Privacy is part of audit.** Prove that an action was governed without
  copying its sensitive content everywhere.
- **Trust is specific and expiring.** Identity, artifact, runtime, action, and
  human trust are separate claims with independent lifecycles.

### 3.1 Decision record: mandatory application signatures

| Dimension | Decision |
|---|---|
| Problem/threat | TLS terminates at proxies and protects a channel, not a queued, relayed, stored, or audited application operation; a valid channel can carry tampered or confused-deputy requests. |
| Design | Every record is COSE-signed by a session key authenticated during the handshake; long-lived objects are separately issuer-signed. TLS exporter context is external authenticated data when available. |
| Alternatives | TLS only; HTTP Message Signatures; long-term identity signature on every message. |
| Tradeoffs | COSE creates a uniform binary envelope and offline verification; HTTP Message Signatures remain useful at HTTP gateways but do not cover non-HTTP transports. Session keys reduce exposure and hardware-signing load but add binding state. |
| Advantages/disadvantages | End-to-end attribution and storage-safe verification at the cost of signature bytes and verification CPU. |
| Security | A signature proves key control, not authorization or host integrity; the remaining checks are still mandatory. Channel binding prevents cross-channel transplant but cannot survive a TLS-terminating gateway unless end-to-end encryption/signing remains intact. |
| Performance | One signature and verification per record; batching is allowed only for stream chunks under Section 18 rules. |
| Compatibility/extensibility | COSE works over HTTP, QUIC, IPC, and queues. Algorithm identifiers use the COSE registry. |

## 4. Threat Model

### 4.1 Assumptions and boundaries

The adversary may control networks, prompts, retrieved data, a model, an agent
process, a tool, a user account, a registry mirror, a dependency, or a host. It
may replay, delay, reorder, truncate, race, and flood traffic. It may possess a
revoked key or a still-valid but overprivileged credential. Cryptographic
algorithms and correctly isolated HSM/TPM boundaries are assumed to meet their
published security goals. Availability against an adversary that can destroy
all replicas or saturate all provisioned capacity is out of scope; bounded,
measurable degradation is in scope.

SMCP does not claim to make a fully compromised endpoint trustworthy. It limits
authority and lifetime, requires observable evidence, supports attestation and
rapid revocation, and prevents one compromised component from silently
borrowing another principal's authority.

### 4.2 Threat and mitigation matrix

| Threat | Required prevention/detection | Limitation / residual risk |
|---|---|---|
| Prompt injection | Data/control separation; provenance labels; model cannot mint capabilities or policy; effect schema; PEP outside model; egress restrictions. | A model may still propose harmful actions that legitimately granted policy permits; consent and narrow capabilities must reflect actual risk. |
| Indirect prompt injection | Mark retrieved/tool/browser content untrusted; preserve origin; prohibit content-to-control coercion; destination and data-class policy. | Semantic classifiers are fallible and cannot be the sole control. |
| Tool/manifest poisoning | Signed manifest digest; trusted publisher policy; TUF metadata; Sigstore/in-toto evidence; schema and effect review; sandbox. | A correctly signed malicious release remains possible; publisher trust, review, monitoring, and rollback are needed. |
| MITM | TLS 1.3/QUIC mutual authentication plus signed records and channel binding. | A compromised endpoint or trusted CA can still impersonate within its scope; pins/federation and revocation reduce exposure. |
| Replay | Session ID, monotonic sender sequence, message ID cache, narrow expiry, challenge nonce, and commit reservation. | Offline recipients need durable replay state; losing it requires epoch rotation before accepting writes. |
| Token/credential theft | Proof-of-possession `cnf`, audience restriction, short life, hardware keys, non-exportability, revocation. | Malware controlling the holder can ask its key to sign; behavioral restrictions and host isolation remain necessary. |
| Privilege escalation | Default deny; capability attenuation; exact audience/resource/action; max delegation; policy at target. | Policy authoring errors remain possible; lint, simulation, review, and audit are required. |
| Supply-chain compromise | TUF rollback/freeze defense, threshold roots, Sigstore transparency, in-toto layouts, SBOM, digest-pinned execution. | Transparency detects but does not prevent all malicious publication; compromised threshold and build systems remain catastrophic. |
| Malicious tool | Sandbox, manifest permissions, per-call capabilities, output taint, network/file allowlists, resource budgets. | Kernel/hypervisor escapes are outside protocol prevention; isolation updates and attestation matter. |
| Compromised agent/model | Model excluded from TCB, narrow expiring capability, two-phase effects, consent, quotas, audit. | Authorized destructive behavior can occur within the grant; minimize grants and use reversible actions. |
| Compromised host | HSM/TPM, measured boot evidence, remote attestation, short sessions, remote revocation. | Attestation is evidence evaluated by policy, not proof of future behavior; secrets exposed before compromise may be lost. |
| Compromised user | WebAuthn user verification, transaction display, separation of duties, velocity/anomaly limits. | A coerced or malicious authorized user can approve harmful operations; dual control may be required. |
| DoS/resource exhaustion | Authenticated discovery, quotas, bounded parsing, credit flow control, deadlines, puzzles only as optional edge defense. | Identity authentication itself consumes resources; stateless cookies and edge filtering are required before expensive checks. |
| Confused deputy | Exact issuer/subject/audience, explicit `act` chain, resource/action binding, no ambient authority, callback destination binding. | Badly modeled resources can alias; canonical resource naming is application-critical. |
| Identity spoofing | Credential chain and proof-of-possession, trust-domain policy, session binding, issuer pinning. | Look-alike display names remain a UI risk; interfaces display canonical IDs and verified organization. |
| Downgrade/protocol confusion | ALPN/content type, domain-separation label, signed negotiation transcript, minimum policy, no fallback. | A user can explicitly configure an obsolete profile; deployments must enforce deprecation policy. |
| Message tampering/truncation | COSE signature, length framing, body digest, sequence and transcript/stream final hash. | Traffic analysis remains unless an anonymity system is layered; SMCP does not provide anonymity. |
| Session hijacking | Ephemeral session signing keys, TLS exporter binding, reauth, key confirmation, sender sequence. | Endpoint memory compromise can steal active keys; isolate and rotate them. |
| Race/TOCTOU | Prepare/commit reservation, resource version and argument/effect digests, short commit deadline, atomic PEP transaction. | External systems without conditional writes may not offer atomicity; adapter must serialize or reject strong-effect operations. |
| Cross-agent attack | Per-agent instance identity, explicit delegation chain, audience isolation, no shared token cache, data provenance. | Colluding authorized agents can combine information; information-flow policy is required for sensitive domains. |
| Audit deletion/equivocation | Hash chains, signed Merkle checkpoints, external witnesses, inclusion/consistency proofs, independent monitors. | A log and all witnesses colluding can hide events; regulated profiles require organizationally independent witnesses. |

### 4.3 Abuse cases

Implementations MUST test at least: a document that says “ignore policy”; a tool
whose new manifest adds network egress; an old valid capability replayed after
delegation revocation; consent displayed for one account and committed against
another; two commits racing on one reservation; a registry serving different
roots to two clients; a relay swapping audiences; an agent replaying a stream
chunk under a new stream; and a gateway claiming legacy content was signed by
the legacy origin.

## 5. Security Goals

### 5.1 Required goals

SMCP provides:

- mutual peer authentication and cryptographic principal binding;
- channel confidentiality, integrity, forward secrecy, and downgrade defense;
- record origin authentication, integrity, freshness, audience restriction, and
  non-repudiation only to the extent the selected credential/key policy permits;
- explicit, least-privilege, proof-of-possession authorization;
- monotonic delegation and prompt revocation;
- human-understandable, transaction-bound consent for governed effects;
- artifact identity and verifiable supply-chain provenance;
- deterministic parsing and bounded resource consumption;
- attributable, tamper-evident, externally witnessed audit;
- crypto, credential, transport, encoding, and version agility without silent
  weakening.

### 5.2 Non-goals

SMCP does not guarantee model correctness, factuality, fairness, availability
under unlimited attack, endpoint safety after total compromise, confidentiality
from the authorized recipient, legal non-repudiation in every jurisdiction, or
semantic equivalence between different application schemas. It does not replace
TLS, OAuth/OIDC, SPIFFE, WebAuthn, RATS, TUF, Sigstore, or in-toto; it composes
profiled forms of them.

### 5.3 Verification targets

The security model is successful only if testable properties hold: authorization
safety (no execution without every predicate), delegation monotonicity, unique
commit, replay rejection, transcript agreement, audit append consistency,
revocation convergence within a declared bound, deterministic decoding, and
cross-implementation signature agreement. Section 33 makes these conformance
requirements, not aspirations.

## 6. Trust Model

Trust is a typed tuple, never a Boolean:

```text
Trust(principal, role, resource, action, environment, evidence, valid_interval)
```

Five independent planes are evaluated:

1. **Identity trust:** who controls the presented key and which authority says
   so.
2. **Authority trust:** what action a capability chain and resource policy allow.
3. **Artifact trust:** which source/build/publisher produced exact bytes.
4. **Runtime trust:** what measured platform currently hosts the workload.
5. **Intent trust:** which human or organizational authority approved the exact
   effect.

Passing one plane never implies another. A SPIFFE SVID authenticates a workload
but does not authorize deletion. A Sigstore bundle authenticates artifact
provenance but does not make the code benign. An attestation describes evidence
and appraisal; it is not authorization. A human login is not transaction
consent.

### 6.1 Trust anchors and federation

Each trust domain publishes a signed Trust Bundle containing domain ID, issuer
keys, allowed credential profiles, capability issuer keys, registry roots,
log/witness keys, policy-signing keys, revocation endpoints, algorithm policy,
and validity interval. Bundle updates use TUF root/targets/snapshot/timestamp
semantics with threshold offline roots. Cross-domain trust requires a signed,
scoped Federation Agreement naming both domains, acceptable credential classes,
resource/action limits, revocation maximum age, and expiry. Transitive federation
is false unless explicitly signed.

WebPKI is an acceptable endpoint bootstrap root, not automatic application
authority. DNSSEC/DANE or configured pins MAY constrain bootstrap. Trust On
First Use is not Core; a Local Pinning profile may use an explicit human-verified
fingerprint and MUST label its lower initial assurance.

### 6.2 Trust lifecycle

`PROPOSED -> VERIFIED -> ACTIVE -> DEGRADED -> SUSPENDED -> REVOKED -> EXPIRED`

- `PROPOSED`: evidence collected, unusable for authorization.
- `VERIFIED`: signatures/chains valid; policy activation pending.
- `ACTIVE`: usable only for its typed scope.
- `DEGRADED`: freshness or posture worsened; only policy-listed low-risk actions.
- `SUSPENDED`: temporarily unusable while investigated.
- `REVOKED`: permanently unusable for times after the signed revocation effective
  time; historical signatures remain verifiable.
- `EXPIRED`: validity ended without implying compromise.

Transitions require signed administrative events. `REVOKED` cannot return to
`ACTIVE`; replacement creates a new trust-anchor version linked by recovery
evidence. Peers cache status no longer than the bundle's `max_staleness`.

### 6.3 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | “Trusted tool/user” collapses unrelated claims and enables lateral privilege. |
| Design | Typed, scoped, expiring trust planes with explicit federation and revocation. |
| Alternatives | Global CA trust, TOFU as default, central reputation score. |
| Tradeoffs | More policy inputs and lifecycle work; substantially smaller implicit trust. |
| Security | Prevents a valid identity or popular artifact from becoming an authorization grant. Evidence issuers can lie, so issuer policy and independent witnesses remain necessary. |
| Performance | Bundles and appraisals are cached to signed freshness limits; verification is off the message hot path after cache fill. |
| Compatibility | SPIFFE/WebPKI/OIDC/DID can supply identity facts; TUF supplies update mechanics. |
| Extensibility | New evidence types register typed claims without redefining authorization. |

## 7. Identity Model

### 7.1 Principal identifier

The canonical identifier is an absolute URI of at most 1024 UTF-8 bytes. Core
supports these profiles:

- `spiffe://trust-domain/path` for workloads and agent/tool instances;
- `https://issuer.example/subjects/<opaque-id>` for federated human and service
  subjects, with issuer metadata pinned by the Trust Bundle;
- `urn:smcp:principal:<base32-sha256>` for locally rooted keys or organizations.

DIDs MAY be accepted only by a registered DID Method Profile that fixes
resolution, update, deactivation, key purpose, canonicalization, and trust-root
rules. A self-asserted DID is not trusted merely because its signature verifies.
Display names are metadata and MUST NOT be used in security comparison.

### 7.2 Composite agent identity

An agent operation identifies independent subjects:

| Claim | Meaning |
|---|---|
| `operator` | Organization accountable for running the agent. |
| `workload` | Running process identity, normally a SPIFFE ID. |
| `agent_instance` | Per-deployment/per-instance principal and session holder. |
| `model_artifact` | Digest and provenance of model weights/API product. |
| `agent_config` | Digest of system policy, tool set, and orchestration configuration. |
| `acting_human` | Human originator when one exists. |
| `purpose` | Policy-defined purpose-of-use identifier. |

Missing optional human/model claims are represented as absent, never guessed.
The workload and instance signer is the record issuer; operator/model/human are
signed supporting claims, not substituted into `iss`.

### 7.3 Credential profiles

- **Workload:** X.509-SVID, one URI SAN SPIFFE ID, short lifetime, federated
  bundle validation, TLS client/server usage as appropriate.
- **Service endpoint:** WebPKI certificate plus application identity credential,
  or X.509-SVID in private federation.
- **Human:** OIDC authorization-code flow with PKCE and exact issuer/audience;
  the authorization service mints a short-lived SMCP session assertion. Raw ID
  or access tokens MUST NOT be forwarded to tools. High assurance uses WebAuthn
  user verification.
- **Device/runtime:** EAT carried as RATS Evidence or Attestation Result, with a
  fresh verifier nonce and appraisal-policy ID.
- **Key principal:** COSE public key anchored in a Trust Bundle or threshold
  recovery document.

All credentials name algorithm, key ID, issuer, subject, audience, not-before,
expiry, assurance level, and status source. Holder proof is required. JOSE may
be used at OIDC boundaries; native SMCP converts verified claims into its signed
CBOR authentication result and does not nest unbounded token chains.

### 7.4 Session keys and binding

Each endpoint creates a fresh record-signing key for a session: ES256 is REQUIRED
for universal interoperability; Ed25519/EdDSA is RECOMMENDED outside restricted
profiles. The long-term credential key signs the authentication proof over:

```text
SHA-256("SMCP-AUTH-v1" || negotiation_transcript_hash ||
       session_public_key_cose || role || credential_digest || nonce)
```

This is a domain-separated signature construction over standard SHA-256 and the
credential's registered signature algorithm; it is not a new primitive. Both
peers confirm the complete transcript in `FINISH`. On TLS transports, the
`TLS-Exporter("EXPORTER-SMCP-Channel-Binding", transcript_hash, 32)` value is
included in COSE external AAD. The exporter is never used to invent or derive an
asymmetric key.

### 7.5 Identity lifecycle and recovery

`UNENROLLED -> ENROLLED -> ACTIVE -> ROTATING -> SUSPENDED -> REVOKED/EXPIRED`

- Enrollment requires out-of-band authority proof and creates an auditable
  principal/key binding.
- Rotation overlaps old/new verification keys for a bounded interval; new keys
  sign a continuity statement and the issuer signs the replacement.
- Suspension blocks new sessions and high-risk current operations.
- Revocation publishes key ID, principal, effective time, reason category, and
  replacement pointer without leaking incident details.
- Recovery uses threshold-authorized offline keys or re-enrollment; possession
  of the compromised key alone cannot authorize recovery.

### 7.6 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Agents are often named by display/model names while credentials identify only a host or OAuth client. |
| Design | URI principals plus composite, issuer-signed agent claims and fresh session keys. |
| Alternatives | One DID per agent; TLS certificate identity only; long-lived API keys. |
| Tradeoffs | Composite identity is more verbose but avoids falsely equating operator, process, model, and human. |
| Security | Fresh keys limit long-term key use and bind records to one transcript. They do not protect a compromised process during the session. |
| Performance | Hardware keys sign once per authentication; fast ephemeral keys sign records. |
| Compatibility | Direct profiles for SPIFFE, WebPKI, OIDC, WebAuthn, EAT; SSH-like pins remain a constrained local profile. |
| Extensibility | Credential profiles are registry entries with mandatory validation algorithms and assurance mapping. |

## 8. Capability Model

An SMCP capability is an issuer-signed, proof-of-possession CWT represented as a
COSE object. It is authority, not identity. Capabilities are never bearer tokens
and MUST contain a `cnf` key/thumbprint identifying the holder key.

### 8.1 Required claims

| Claim | Meaning and validation |
|---|---|
| `cap_id` | 128-bit random identifier, unique per issuer; replay/status key. |
| `iss`, `sub` | Issuer and authorized holder principal. |
| `aud` | Exact resource-service principal; wildcard forbidden. |
| `iat`, `nbf`, `exp` | Integer epoch milliseconds; maximum life is profile bounded. |
| `cnf` | RFC 8747-style confirmation of the holder's session or delegated key. |
| `actions` | Non-empty registered action identifiers. |
| `resources` | Canonical resource selectors with type and tenant/domain. |
| `constraints` | Argument predicates, data classes, destinations, quotas, time, network zone, purpose, runtime/attestation, and effect limits. |
| `parent_digest` | SHA-256 of the complete parent token; absent only for root grants. |
| `delegation` | Remaining depth, permitted delegate selectors, and `redelegable` flag. |
| `rev_epoch` | Issuer revocation epoch required at verification. |
| `policy_hash` | Optional minimum policy set that the resource must apply, never a policy bypass. |

Resource selectors MUST be canonical and closed over an explicitly named
namespace. A filesystem selector, for example, contains filesystem authority,
root object ID, normalized relative path, symlink policy, and allowed operations;
it is not merely an ambiguous path string.

### 8.2 Attenuation relation

For child `C` and parent `P`, validation requires:

```text
C.audience       = P.audience
C.actions        subset-of P.actions
C.resources      subset-of P.resources
C.constraints    implies P.constraints
C.not_before     >= P.not_before
C.expiry         <= P.expiry
C.quota          <= remaining(P.quota)
C.delegate_depth < P.delegate_depth
C.parent_digest  = SHA-256(P.encoded_bytes)
C.issuer         = P.subject
holder(C) permitted-by P.delegate_selector
```

Constraint implication is decidable only within the registered constraint
language. An unknown or non-provable implication is rejection, not delegation.
The chain length is limited by profile (Core default 4, absolute maximum 8).

### 8.3 Reference and presentation

A request may carry the complete capability chain or a `cap_ref` digest. A
reference is usable only after the same audience has cached and verified the
complete chain in the same trust/revocation epoch. Cache miss produces
`CAPABILITY_REFERENCE_UNKNOWN`; it never triggers authority by lookup from an
untrusted URI. Capabilities are encrypted in transit and redacted from logs.

### 8.4 Capability lifecycle

`REQUESTED -> ISSUED -> ACTIVE -> ATTENUATED -> EXHAUSTED/EXPIRED/REVOKED`

Issuance is an auditable authorization operation. Usage atomically consumes
quota at the resource or its authoritative quota service. Delegation creates a
new child; it does not mutate the parent. Revocation may target a token, an
ancestor subtree, subject, key, or issuer epoch. Offline operation is permitted
only when the capability embeds an offline allowance, maximum offline interval,
and monotonic counter source; mutating offline operations otherwise fail.

### 8.5 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Ambient credentials and coarse OAuth scopes enable confused deputies and stolen-token replay. |
| Design | Audience-specific, holder-bound, attenuating CWT capabilities with exact resources, actions, constraints, quota, and revocation epoch. |
| Alternatives | Bearer JWTs, ACL/RBAC only, macaroons, proprietary signed grants. |
| Tradeoffs | CWT/COSE and a restricted implication language maximize standard interoperability; macaroons offer elegant attenuation but add a separate token family and verifier model. |
| Security | PoP stops off-device bearer replay, not misuse by compromised holder code. Exact audience/resource limits that blast radius. |
| Performance | Reference caching makes steady-state requests carry a 32-byte digest; quota updates may require a consistency service. |
| Compatibility | OAuth tokens can be exchanged for native capabilities at a Security Token Service; they are not passed through blindly. |
| Extensibility | Constraint types use a registry; unknown critical constraints fail. |

## 9. Authorization Model

Authorization is performed for every operation, including discovery details,
capability issuance, consent solicitation, subscription, audit query, and
administrative recovery. Session establishment authorizes only protocol traffic;
it grants no resource action.

Every record has an authorization context. Handshake/close/error records are
authorized by the local endpoint-admission policy, legal state, authenticated
transcript facts available at that stage, and strict rate/size limits; they do
not require a resource capability. Stream chunks and events inherit only the
signed, still-valid authority of their parent operation/stream/subscription and
are continuously subject to credit, expiry, classification, and revocation.
All other established-session messages present a capability for their registered
protocol or resource action. Thus “protocol plumbing” is never ambient authority.

### 9.1 Authorization input

The PEP constructs an immutable Authorization Input:

```text
principal: verified issuer, composite actors, assurance, credential status
action: registered action and declared effect class
resource: canonical ID, owner, tenant, type, current version, classification
context: time, session, transport, network zone, purpose, request digest
authority: verified capability chain, remaining quotas, revocation freshness
artifact: manifest digest, publisher, provenance, vulnerability policy result
runtime: attestation appraisal and freshness
content: origin/taint labels and intended destinations (never executable policy)
risk: signed assessment and required controls
consent: verified receipt or absence
```

The input is encoded deterministically and hashed. The decision returns this
hash, policy bundle hash/epoch, result, obligations, and maximum decision age.
The PEP MUST reject a decision for any other input hash.

### 9.2 Decision algorithm

The resource-side PEP MUST perform the following order. Parallel validation is
allowed, but all results must correspond to one resource snapshot.

1. Verify channel, record signature, session, audience, time, sequence, and
   critical extensions.
2. Verify credential status and session-key binding.
3. Resolve and verify the complete capability chain, quota, and revocation.
4. Verify the signed manifest and artifact/runtime requirements.
5. Normalize the resource and arguments using the operation schema.
6. Evaluate local policy using the immutable input.
7. Obtain risk restrictions if policy requires them.
8. Re-evaluate policy with risk evidence and determine obligations.
9. Verify consent, dual control, sandbox, rate, logging, and other obligations.
10. Reserve resource version and quota for side effects.
11. Return a signed decision/preparation receipt.

An explicit `forbid` overrides every permit. No matching permit is deny. A PDP
error or missing fact is `INDETERMINATE`, which the PEP treats as deny. Policy
may further narrow capabilities but cannot widen them. A capability issuer
cannot force a resource owner to allow an action.

### 9.3 Resource and action naming

Actions are URIs, for example `urn:smcp:action:fs.read` and
`urn:example:crm:customer.update`. Resources are typed canonical URIs whose
scheme profile defines normalization and comparison. The profile MUST eliminate
aliases or include the authoritative object ID. Unicode identifiers are NFC
normalized; security comparison uses encoded canonical bytes, not locale rules.
Query fragments, relative paths, and display labels are forbidden as sole
security identifiers.

### 9.4 Obligations

Registered obligations include: human consent, user verification, dual control,
fresh attestation, sandbox class, network isolation, data redaction, purpose
binding, maximum result size, audit-before-execute, external witness receipt,
rate/quota, reversible mode, dry run, and delay/cooling-off period. The PEP MUST
understand and prove completion of every critical obligation before commit.

### 9.5 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Authentication or a broad token is often mistaken for permission. |
| Design | Target-side intersection of record, identity, capability, policy, risk restrictions, consent, trust, and quota over one snapshot. |
| Alternatives | RBAC only; gateway-only enforcement; authorization by the agent/model. |
| Tradeoffs | More inputs and occasional network calls; deterministic, explainable decisions at the actual resource boundary. |
| Security | Default/error deny and deny-overrides prevent gaps from becoming grants. A malicious resource owner can ignore its PEP; callers use signed receipts and attestation where that matters. |
| Performance | PDP and status results are cached to their signed validity; prepare is the synchronization point. |
| Compatibility | Maps to Kubernetes admission/authorization, OAuth RAR, and AuthZEN without adopting their bearer assumptions. |
| Extensibility | Typed obligations and resource profiles can grow through registries. |

## 10. Delegation Model

Delegation records who is acting for whom and transfers only an attenuated
capability. Identity impersonation is never delegation. The record issuer
remains the immediate actor; the ordered actor chain is carried in `actors`.

### 10.1 Delegation procedure

1. Delegate authenticates and provides its holder public key.
2. Delegator selects one parent capability with `redelegable=true`.
3. Delegator constructs child claims satisfying Section 8.2.
4. A local PDP authorizes `urn:smcp:action:capability.delegate` for the child
   digest; any required owner or human consent is obtained.
5. Delegator signs `CAP_DELEGATE`; the capability issuer or authorized Security
   Token Service issues the child and records the parent digest.
6. Audience verifies every link and the actor chain at use time.

The child `sub` must control `cnf`. A service may not delegate to a key it also
controls while representing it as an independent agent. An on-behalf-of chain
is ordered from original authority to immediate actor and is limited to eight
entries. Omitting or reordering an actor is signature failure.

OAuth deployments SHOULD use RFC 8693 token exchange and RFC 9396 authorization
details at the boundary, then mint a native SMCP PoP capability. OAuth access
tokens and refresh tokens MUST NOT appear in an SMCP operation body.

### 10.2 Revocation propagation

Revoking an ancestor invalidates every descendant. Issuers publish a signed
append-only revocation sequence and compact status set for `(issuer, epoch)`.
Online high-risk operations require a status proof no older than 60 seconds;
Core's general maximum is 5 minutes; profiles may shorten but not lengthen it
for side effects. A delegation tree cache invalidates atomically on epoch change.

### 10.3 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Shared tokens erase attribution and permit authority amplification. |
| Design | Issuer-visible child capabilities, holder keys, parent hashes, actor chain, bounded depth, subset proof. |
| Alternatives | Token forwarding; identity impersonation; unconstrained OAuth token exchange. |
| Tradeoffs | Additional issuance and chain validation; exact accountability and revocation. |
| Security | Monotonicity is machine-checkable for registered constraints. Semantic aliases in a bad resource profile can still violate subset assumptions. |
| Performance | Depth is bounded; validated chains may be cached by digest and epoch. |
| Compatibility | Token exchange provides a bridge while SMCP retains target-native semantics. |
| Extensibility | New delegation constraints must define a decidable subset relation. |

## 11. Consent Model

Consent is a signed, purpose-limited authorization fact from a human or
organizational consent authority. It is neither a disclaimer nor a generic
“Allow” click. A model, agent, tool, or resource cannot consent on behalf of a
human unless a separately signed organizational policy explicitly names that
principal and the action does not require human presence.

### 11.1 Consent request

`CONSENT_REQUEST` binds:

- request and preparation IDs;
- requesting and acting principals, capability-chain digest, and recipient;
- canonical action and resource snapshot;
- normalized argument digest and a non-authoritative display projection;
- manifest digest and declared effect class (`read`, `write`, `execute`,
  `external-communicate`, `financial`, `identity`, `privilege`, `destructive`);
- input/output data classifications and destinations;
- purpose, reversibility, rollback window, worst-case cost, and alternatives;
- requested validity, use count, and required authenticator assurance;
- a fresh 256-bit challenge.

The display projection is generated from the signed typed operation schema, not
from model prose. The consent UI MUST show verified canonical destination and
effect, distinguish requested from already granted authority, and prevent tool
content from drawing inside trusted UI chrome.

### 11.2 Consent response and proof

The authority returns `CONSENT_RESPONSE` with `approve` or `deny`, request digest,
approved/narrowed fields, time, expiry, maximum uses, authenticator data, and
revocation endpoint/epoch. High-risk profiles require a WebAuthn assertion with
user verification and a transaction hash in the challenge. The SMCP consent
service then signs a COSE Consent Receipt after validating origin, RP ID,
challenge, counter/backup policy, and user verification.

Consent cannot broaden the capability or override policy. Narrowing is allowed.
Any change to action, canonical resource, arguments, effect, destination,
manifest, acting principal, purpose, or resource version invalidates the receipt.
The PEP atomically consumes a use with commit.

### 11.3 Lifecycle

`ABSENT -> REQUESTED -> APPROVED/DENIED -> CONSUMED -> EXPIRED/REVOKED`

- Requests expire after at most 10 minutes in Core; high-risk profiles use 2.
- Approval is valid at most 15 minutes and one use for mutating/high-risk actions.
- Standing consent requires a Regulated policy profile, explicit resource/action
  bounds, periodic renewal, and a visible revocation control.
- Denial is signed when non-repudiable workflow evidence is required; its reason
  text is private and optional.
- Revocation blocks uncommitted operations. A commit already atomically accepted
  may complete, but its receipt records whether cancellation was possible.

### 11.4 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Generic consent can be phished, replayed, or shown for a harmless action then used for a different effect. |
| Design | Schema-derived transaction display, signed exact-effect receipt, WebAuthn for high risk, single-use atomic consumption. |
| Alternatives | OAuth consent screen, chat confirmation, OS permission prompt. |
| Tradeoffs | User friction for sensitive effects; low-risk reads can be preauthorized by policy without per-call prompts. |
| Security | WebAuthn proves user interaction/verification and origin binding, not comprehension or freedom from coercion. Dual control and cooling-off address higher risk. |
| Performance | Consent adds human latency only when policy requires it; receipts cache no broader authority. |
| Compatibility | WebAuthn and OIDC identities remain standard; non-browser authenticators use equivalent registered profiles. |
| Extensibility | Effect vocabularies and display renderers are signed schema profiles, never arbitrary HTML. |

## 12. Policy Language

The normative policy semantics use the Cedar authorization model: principal,
action, resource, and context; explicit `permit` and `forbid`; default deny; and
forbid-overrides. SMCP defines a Cedar Profile rather than a new policy language.
Remote PDPs expose the OpenID AuthZEN Authorization API 1.0 profile with signed
SMCP request/response wrappers.

### 12.1 SMCP Cedar Profile

The profile requires:

- a published entity schema and action/resource registry;
- no network, filesystem, clock, random, model, or plugin calls during evaluation;
- all external facts supplied as typed, signed context;
- Unicode NFC and exact byte comparison for IDs;
- integer time in epoch milliseconds and bounded integer arithmetic;
- deterministic extension functions from the SMCP registry only;
- policy bundles signed by an authorized policy key and identified by SHA-256;
- static validation, forbidden-action linting, and maximum evaluation budget;
- `forbid` precedence and error/unknown-to-deny at the PEP.

CEL MAY be registered for constraint predicates because it is bounded and
non-Turing-complete, but it is not the Core authorization policy format. OPA/Rego
adapters may be deployed only if they reproduce Core decision and error semantics
and declare their non-portable policy type.

### 12.2 Example (non-normative)

```cedar
permit (
  principal is Smcp::Agent,
  action == Smcp::Action::"fs.read",
  resource is Smcp::File
)
when {
  principal.operator == resource.owner &&
  context.capability.actions.contains("urn:smcp:action:fs.read") &&
  context.purpose == "urn:example:purpose:build"
};

forbid (principal, action, resource)
when { resource.classification == "secret" && !context.runtime.measured };
```

Capability verification occurs before policy; the example's capability check is
illustrative defense in depth, not a substitute for the verifier.

### 12.3 Policy distribution and change

Bundles contain schema, policies, tests, issuer, sequence, activation time,
expiry, previous digest, and rollback authorization. Distribution uses TUF.
Activation is atomic. A policy sequence cannot decrease without threshold-signed
recovery metadata. Prepared operations bind the policy digest/epoch and are
invalidated by a security-emergency update; normal updates may honor existing
preparations only within their stated maximum age.

### 12.4 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Ad hoc policy languages differ in deny/error behavior and may let the model fetch facts or execute code. |
| Design | Cedar profile for local deterministic policy; AuthZEN profile for remote decision interoperability. |
| Alternatives | Invent a DSL; Rego; CEL alone; XACML. |
| Tradeoffs | Cedar's typed, analyzable model is less general than arbitrary code; that restriction is a security advantage. AuthZEN adds remote latency when used. |
| Security | Pure evaluation reduces policy injection and nondeterminism. Signed bad policy can still authorize harm; review, simulation, separation of duties, and rollback are required. |
| Performance | Bounded local evaluation; precompiled bundles and fact caching. |
| Compatibility | Adapters can translate platform RBAC/admission facts, but portable profiles use native Cedar entities/actions. |
| Extensibility | Registry-approved pure functions and schemas evolve independently of wire version. |

## 13. Risk Engine

The Risk Engine is a restriction oracle, never an authority source. Its output is
a signed `RISK_ASSESSMENT` over the authorization-input digest, engine/model/rule
version, observed factors, confidence, validity, and required controls.

### 13.1 Mandatory factors

Every conformant engine accepts: identity assurance/status, credential age,
delegation depth and breadth, capability lifetime/quota, action effect,
resource/data classification, external destination, content provenance/taint,
manifest and artifact provenance, attestation freshness, anomaly/velocity,
network/region/time, prior denials, and human-presence state. A factor may be
`unknown`; unknown high-impact factors cannot be silently assigned low risk.

### 13.2 Outcomes

- `BLOCK`: final denial.
- `RESTRICT`: add narrower resource/argument/result/egress/quota limits.
- `REQUIRE`: add controls such as consent, WebAuthn UV, dual approval, fresh
  attestation, sandbox, dry-run, delay, or witness receipt.
- `OBSERVE`: no additional restriction, with signed evidence for policy. This
  is not an allow decision.

Numeric scores are local diagnostics and MUST NOT be interpreted across engines.
Interoperability uses the ordered outcome and registered controls. ML-based risk
classifiers must identify model/version/training-policy provenance, operate
outside the requesting model, and have deterministic rule fallback.

### 13.3 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Opaque “trust scores” can silently grant access, drift, or be manipulated by the same model requesting action. |
| Design | Signed, input-bound, short-lived restrictions with standardized outcomes and factors; risk cannot grant. |
| Alternatives | Static policy only; global reputation score; model self-evaluation. |
| Tradeoffs | Dynamic defense and anomaly response at cost of operational complexity and potential false positives. |
| Security | Fail-safe direction prevents a low score from bypassing authority. Engine compromise can cause denial or omit restrictions; policy still sets the maximum grant. |
| Performance | Parallel evaluation and short caching; high-risk policy may require fresh synchronous evidence. |
| Compatibility | Vendors can use different scoring internals while emitting interoperable controls. |
| Extensibility | New factors/controls register semantics, privacy class, and safe unknown behavior. |

## 14. Audit System

SMCP audit is a verifiable event system, not application logging. Each security
event is COSE-signed by its emitter, deterministically encoded, hash-linked per
emitter, and committed to a Merkle transparency log. The system aims for
tamper-evidence, attribution, ordering evidence, and detectable equivocation; it
does not describe data as immutable when all copies can be destroyed.

Every received and sent protocol record is auditable. Its exact signed-record
digest, direction, sequence, disposition, and error/result code are appended to
a per-session Merkle accumulator. A signed session checkpoint commits the root,
record count, first/last sequence in each direction, and preceding checkpoint.
High-volume stream/event records may be represented by accumulator leaves rather
than individual semantic events, but no record may be omitted. Authentication,
authority, consent, risk, manifest/trust, operation, and administrative records
also create the typed events below. This distinction meets complete message
accountability without copying sensitive payloads into an audit warehouse.

### 14.1 Audit event

An event contains: event ID; event type; emitter principal/key; subject/actors;
session/message/correlation/preparation/commit IDs as applicable; timestamp and
trusted-time quality; action and canonical resource digest; decision and reason
codes; capability/consent/policy/risk/manifest/attestation digests and epochs;
effect/result class; byte/count/cost metrics; privacy labels; previous-event
hash; encrypted-detail reference; and signature.

Default records contain hashes and classifications, not prompts, content,
credentials, capability bytes, consent authenticator data, secrets, raw
arguments, or personal data. A policy may store encrypted details under a
separate audit-encryption key with access logged and retention bounded.

### 14.2 Ordering and durability

For a side effect, the PEP MUST durably append `operation.intent` and
`authorization.decision` before execution, then `operation.commit` and
`operation.result`. It uses an atomic outbox or a storage transaction that
couples the reservation/effect to the audit append. If required durable audit is
unavailable, mutation fails with `AUDIT_UNAVAILABLE`; buffering alone is
insufficient for high-risk profiles. Low-risk read profiles may use a bounded,
encrypted local spool only when policy explicitly permits it.

Each emitter maintains `prev_hash` and monotonic `event_seq`. A log returns a
signed inclusion promise, later an RFC 9162-style inclusion proof and signed
tree head. Clients and independent witnesses exchange tree heads and verify
consistency. Split-view detection requires gossip/monitoring; Merkle trees alone
do not prevent a malicious log from presenting two histories.

### 14.3 Lifecycle and retention

`CREATED -> LOCALLY_DURABLE -> SUBMITTED -> PROMISED -> INCLUDED -> CHECKPOINTED -> ARCHIVED -> DISPOSED`

Events not included by their maximum merge delay trigger an alert and block the
emitter's high-risk operations. Archive packages include signed tree heads,
consistency/inclusion proofs, trust bundles, policy/manifests, algorithm IDs,
and verification software metadata needed for long-term validation. Disposal is
a signed tombstone containing only event ranges, policy basis, and aggregate
commitment; cryptographic erasure destroys per-record data keys.

### 14.4 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Local logs can be edited, selectively deleted, flooded with secrets, or forked. |
| Design | Signed hash-chained minimal events, transactional intent logging, transparency inclusion and external witnesses, encrypted detail separation. |
| Alternatives | Append-only database; blockchain; centralized SIEM; full payload capture. |
| Tradeoffs | Proof and witness infrastructure adds latency/storage; avoids blockchain consensus and privacy leakage. |
| Security | Detects tampering/equivocation when at least one honest copy/witness exists. It cannot recover evidence destroyed everywhere or guarantee event truth from a compromised signer. |
| Performance | Hash/sign per event, batched Merkle inclusion; payload commitments bound storage growth. |
| Compatibility | RFC 9162 proof patterns and standard COSE objects support independent verifiers and SIEM export. |
| Extensibility | Event types and privacy labels are registries; unknown events remain cryptographically verifiable. |

## 15. Tool Manifest Specification

Every executable tool/version has a signed `ToolManifest`. Discovery metadata is
not sufficient. The manifest's deterministic encoded bytes are content-addressed
by SHA-256 and signed by the publisher; a registry countersignature means only
that publication policy was met.

### 15.1 Required fields

| Field | Requirement |
|---|---|
| `manifest_version` | SMCP manifest major/minor and critical extensions. |
| `tool_id`, `version` | Canonical publisher-scoped URI and semantic or immutable version. Mutable tags are prohibited for execution. |
| `publisher` | Principal, signing key ID, support/security contacts. |
| `artifact` | Media type, platform, immutable SHA-256 digest, size, retrieval references. |
| `entrypoints` | Action IDs and exact input/output CDDL or JSON Schema digest/reference. |
| `effects` | Per action: reads, writes, executes, external communication, financial, identity, privilege, destructive; resources and reversibility. |
| `permissions` | Filesystem roots, network destinations/protocols, APIs, devices, environment/secrets, process and cloud permissions, all default-deny. |
| `data_practices` | Input/output classification, retention, training/use, regions, subprocessors, egress. |
| `limits` | CPU, memory, storage, wall time, output bytes, calls, concurrency. |
| `sandbox` | Required isolation class, syscalls/capabilities, user/namespace/network policy, privilege. |
| `dependencies` | SBOM digest/media type, transitive artifact digests, license metadata. |
| `provenance` | in-toto/SLSA statement digest, Sigstore bundle, builder identity, source and build digest. |
| `updates` | TUF repository/targets role, delegated path, rollback and expiry policy. |
| `attestation` | Required runtime evidence types, measurements/reference values, freshness. |
| `consent_policy` | Effect-specific minimum consent/display/assurance; resource policy may strengthen it. |
| `risk_hints` | Signed factual risk inputs, never a self-awarded reputation or grant. |
| `deprecation` | Status, end-of-support time, replacement, known unsafe actions. |

Schemas MUST be closed (`additionalProperties=false` or equivalent) for
security-relevant inputs. Every effectful field must be derived from the typed
input. A tool that discovers an undeclared required permission MUST fail and
publish a new manifest; runtime “allow anyway” prompts are forbidden.

### 15.2 Verification and reputation

Before first use and on every digest/epoch change, the verifier checks publisher
trust, signature, TUF freshness/version, artifact digest, provenance subject,
SBOM policy, transparency inclusion, manifest/action schema, sandbox capability,
and revocation. The execution receipt includes the manifest and artifact digest.

Reputation consists of signed observations: assessor, subject digest, metric
definition, evidence window, sample count, confidence, conflicts of interest,
expiry, and privacy category. No global numeric score is standardized. Policy
may use trusted observations only to add restrictions or satisfy an explicitly
named evidence requirement; popularity never grants authority.

### 15.3 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Names and self-described tool schemas do not prove code identity, effects, permissions, or build origin. |
| Design | Digest-addressed publisher-signed manifest tied to artifact, schemas, effects, sandbox, SBOM, in-toto/Sigstore provenance, and TUF updates. |
| Alternatives | Package signature only; registry review badge; container image name; MCP tool description. |
| Tradeoffs | Publication burden and strict permission declarations; reproducible, enforceable install/run decisions. |
| Security | A signed malicious tool remains malicious; sandbox, policy, review, behavior monitoring, and revocation are independent layers. |
| Performance | Verification is cached by immutable digest; execution adds no manifest parsing on a warm path. |
| Compatibility | OCI, SPDX/CycloneDX, in-toto, Sigstore, and TUF evidence can be referenced without conversion. |
| Extensibility | Media types and evidence/sandbox profiles are registered and critical when required. |

## 16. Discovery Protocol

Discovery has a public bootstrap phase and an authenticated normative phase.
The HTTPS resource `/.well-known/smcp` returns minimal signed bootstrap metadata:
service principal, protocol versions, endpoint URIs, transport profiles, trust
bundle reference/digest, registry/log references, metadata expiry, and signature.
It MUST NOT expose tool inventory, tenant details, policy, or resource existence.

The client validates HTTPS origin, metadata signature, exact service identity,
expiry, and trust bundle before connecting. After authentication, it sends
`DISCOVER` with requested service/action categories, privacy budget, and a valid
capability for non-public metadata. The signed `DISCOVERY_RESULT` contains only
authorized entries and includes manifest digests rather than trusting prose.

DNS SVCB/HTTPS records MAY advertise the well-known origin and ALPN, but DNS is
not application identity unless DNSSEC/DANE is an accepted bootstrap profile.
mDNS and broadcast discovery are forbidden outside the Local profile; even
there, results require explicit pin/trust validation before authentication.
Directory enumeration resistance requires uniform unauthorized/not-found errors
and policy-controlled result padding/bucketing for sensitive deployments.

### 16.1 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Discovery leaks attack surface and poisoned metadata redirects clients or forces downgrade. |
| Design | Minimal signed HTTPS bootstrap followed by authenticated, authorized, capability-limited discovery. |
| Alternatives | Anonymous registry search; DNS-only; configuration-only. |
| Tradeoffs | One authenticated step before rich discovery; far less inventory leakage and metadata poisoning. |
| Security | WebPKI compromise remains a bootstrap risk unless constrained by bundle/pin/DANE; signed expiry and identity prevent cache substitution. |
| Performance | Well-known metadata is cacheable to expiry; private queries can paginate. |
| Compatibility | Mirrors established well-known/OAuth resource metadata patterns and works behind HTTP infrastructure. |
| Extensibility | Signed metadata carries critical extension and profile registries. |

## 17. Registry Specification

SMCP registries are federated catalogs, not universal trust authorities. A
registry stores signed immutable objects and indexes their verified attributes.
Objects include Trust Bundles, Federation Agreements, Tool Manifests, policy
bundles, revocations, schema packages, extension definitions, and transparency
checkpoints.

### 17.1 Publication

Publication is an authenticated SMCP operation requiring a publisher capability.
The registry validates object syntax/signature, publisher namespace ownership,
TUF sequence/freshness, schema closure, referenced digest consistency,
transparency policy, and size limits. It records the original bytes unchanged,
returns a signed publication receipt, and submits the object digest to a
transparency log. Acceptance is not an endorsement.

Names map to immutable versions. Replacing bytes under an existing digest or
version is impossible. A mutable channel such as `stable` is a separately signed
TUF target mapping with monotonically increasing metadata. Deletion becomes a
signed tombstone; historical proofs remain.

### 17.2 Query and federation

Queries are signed, authenticated, authorized, bounded, and privacy-audited.
Results contain object bytes or digests, publisher signatures, registry receipt,
TUF path, transparency inclusion proof/promise, expiry, and pagination cursor
bound to the query digest. Ranking data is explicitly non-security metadata.

Federation uses signed cross-registry statements specifying namespaces, trust
roots, validation profile, log/witness set, maximum staleness, and expiry. A
client applies its own policy to every remote object. Registries MUST NOT
transitively assert trust absent a Federation Agreement.

### 17.3 Availability and consistency

Clients use multiple mirrors, TUF snapshot/timestamp metadata, monotonic local
versions, and log consistency proofs to detect rollback, freeze, and split view.
Security-critical cached objects may be used only until their signed expiry and
profile staleness bound. If all registries are unavailable, existing sessions
may perform only operations whose complete trust/capability/revocation evidence
is fresh in cache; no new trust or manifest version is inferred.

### 17.4 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | A central registry becomes a global compromise, censorship, rollback, and privacy point. |
| Design | Federated stores of issuer-signed immutable objects, TUF freshness, transparency receipts, client-side trust policy. |
| Alternatives | Central app store; DNS registry; blockchain namespace. |
| Tradeoffs | More proof material and federation governance; avoids one registry becoming root authority. |
| Security | Registry compromise can hide/delay data until freshness expires but cannot forge publisher bytes; colluding roots/logs remain a trust-domain failure. |
| Performance | Mirrors, digest caches, and compact proofs; authenticated query adds signature cost. |
| Compatibility | HTTP content distribution and OCI-style blobs may carry objects while SMCP secures publication/query semantics. |
| Extensibility | New object types register validation and privacy rules. |

## 18. Protocol Messages

The normative CDDL is `smcp-v1.cddl`. This section defines semantics. A peer
MUST reject a message whose body does not match the type selected in both the
protected COSE header and envelope. Requests that expect a reply contain
`request_id`; replies copy it as `in_reply_to`. Error replies are signed records.

### 18.1 Common envelope fields

| Field | Type | Requirement |
|---|---|---|
| `version` | `[major, minor]` | Selected session version; exact match required after negotiation. |
| `type` | unsigned integer | Registered message type; must equal protected header type. |
| `msg_id` | 16-byte string | Cryptographically random and unique per sender key. |
| `issuer` | principal URI | Principal controlling the record-signing key. |
| `audience` | non-empty principal URI array | Exact intended verifier(s); receiver must be present. |
| `issued_at`, `expires_at` | epoch milliseconds | Freshness interval; `expires_at > issued_at`; Core maximum 5 minutes, except signed long-lived objects carried as body. |
| `session_id` | 32-byte string | Negotiated session; all zero only for initial `CLIENT_HELLO`. |
| `seq` | unsigned integer | Strictly increasing per sender/session starting at zero. |
| `correlation_id` | optional 16-byte string | Workflow correlation; not authorization. |
| `capabilities` | capability/reference array | Authority presented for this message; empty only where explicitly allowed. |
| `consent_ref` | optional digest | Consent receipt digest; full receipt is attached or in verified session cache. |
| `extensions` | map | Registered extension ID to deterministic value; critical IDs are also protected. |
| `body` | typed map | Exactly one schema selected by `type`. |

Handshake message expiry is at most 60 seconds. Operation messages default to
30 seconds. Receivers use a trusted clock and allowed skew of at most 60 seconds;
profiles may reduce it. When reliable time is unavailable, a nonce challenge and
online status proof are mandatory and expiry is still enforced by the issuer's
time source.

### 18.2 Handshake and lifecycle messages (1–9)

| Code / name | Body and behavior |
|---|---|
| 1 `CLIENT_HELLO` | Random `client_nonce`, ordered supported versions/suites/transports/encodings/compressions, client session public key, credential-profile list, critical extensions, limits, optional stateless retry cookie. Signed by that session key; no capability required. |
| 2 `SERVER_HELLO` | Echoed client nonce, fresh server nonce/session ID, one selection from each offered set, server session key, server credential profile, limits, retry state, transcript hash through both hellos. Selection outside the offer is fatal. |
| 3 `AUTHENTICATE` | Role, credential chain/reference, credential digest, long-term-key proof over Section 7.4 binding, optional fresh EAT evidence, requested trust domain. Sensitive credentials are never audit logged. |
| 4 `AUTH_RESULT` | `accepted` or coded denial, authenticated principal/composite claims, assurance level, credential/status expiry, trust-domain and policy epoch. It carries no resource authorization. |
| 5 `FINISH` | Transcript hash including authentication results and TLS exporter binding; sender's first accepted receive sequence and negotiated limit digest. Application messages are illegal until both FINISH records verify. |
| 6 `REAUTH` | Fresh challenge, requested credential/attestation profiles, reason, deadline. Existing authority may be suspended while pending. |
| 7 `REKEY` | New session public key, current-key signature, activation sequence, key epoch. Both keys are accepted only across a maximum 32-record overlap. |
| 8 `CLOSE` | Reason, last sent/received sequence, stream summaries, audit checkpoint request, drain deadline. No new operations after sending/receiving. |
| 9 `CLOSE_ACK` | Close digest, final sequences, final audit receipt(s). The peer then erases session secrets and replay state only after the durable retention interval. |

A rejected handshake uses an ephemeral signed `ERROR` and closes without
revealing whether a particular principal exists. Authentication attempts are
rate-limited by network origin and retry cookie before expensive validation.

To make the rolling transcript deterministic under full-duplex transports, the
Core handshake has one total order: initiator `CLIENT_HELLO`, responder
`SERVER_HELLO`, initiator `AUTHENTICATE`, responder `AUTHENTICATE`, responder
`AUTH_RESULT`, initiator `AUTH_RESULT`, initiator `FINISH`, responder `FINISH`.
A peer MUST reject an otherwise valid handshake record received in another
turn. This order is a protocol ordering rule, not a transport half-duplex
requirement. It removes arrival-race ambiguity and makes both transcript views
identical without trusting clocks or local scheduling.

### 18.3 Discovery messages (16–17)

- `DISCOVER` includes category/action filters, manifest/profile constraints,
  maximum results, cursor, response-field mask, and privacy budget. Private
  discovery requires a `registry.query` or service-specific capability.
- `DISCOVERY_RESULT` includes query digest, signed entries (service principal,
  endpoint, action categories, manifest digest, profile requirements), next
  cursor, result expiry, registry proof, and optional uniform-size padding.

### 18.4 Capability and revocation messages (32–37)

- `CAP_REQUEST`: desired audience/actions/resources/constraints/lifetime,
  holder key, parent reference, purpose, and authorization-details digest.
- `CAP_GRANT`: granted capability chain, status endpoint, revocation epoch,
  excluded/narrowed fields, and issuance audit receipt.
- `CAP_DELEGATE`: parent bytes/reference, exact child request, actor chain,
  policy/consent evidence, and holder proof.
- `CAP_REVOKE`: target kind and ID/digest, effective time, reason category,
  cascade flag, issuer epoch, and replacement pointer; it requires administrative
  capability and appropriate dual control.
- `REVOCATION_QUERY`: issuer, epoch, token/key/subject identifiers, nonce, and
  required freshness.
- `REVOCATION_STATUS`: nonce, issuer/epoch/sequence, per-target good/revoked/
  suspended/unknown status, effective times, next update, and proof/checkpoint.

`good` means only “not revoked in this authoritative status set at this
sequence”; the receiver still verifies all other conditions.

### 18.5 Consent and risk messages (48–50, 64–65)

- `CONSENT_REQUEST`, `CONSENT_RESPONSE`, and `CONSENT_REVOKE` carry the exact
  fields and lifecycle defined in Section 11. Denial is never represented by an
  absent or timed-out approval.
- `RISK_REQUEST` carries authorization-input digest, requested factor classes,
  evidence references, privacy budget, engine nonce, and required response time.
- `RISK_ASSESSMENT` carries the outcome, registered factor findings, required
  controls/restrictions, engine/policy/model version, confidence semantics,
  nonce, issued/expiry, and input digest. Missing requested factors are explicit.

### 18.6 Operations (80–86)

`OP_REQUEST` is a one-phase operation permitted only for actions whose manifest
and resource policy classify them as read-only, idempotent, and without external
communication or authority change. It contains action, resource, normalized
arguments, argument-schema digest, manifest digest, deadline, idempotency key,
result constraints, and authorization evidence. The result includes snapshot
version so a later mutation cannot treat stale data as current.

All other operations use:

1. `OP_PREPARE`: action, resource, normalized arguments, schema/manifest digests,
   declared effects/destinations/cost, expected resource version, deadline,
   idempotency key, rollback preference, and evidence.
2. `OP_PREPARED`: preparation ID, request/body/effect/input hashes, authoritative
   normalized effect preview, reserved resource version/quota, policy/risk/
   capability/manifest/revocation epochs, unmet obligations, consent-request
   digest if needed, commit deadline, and signed decision receipt.
3. `OP_COMMIT`: preparation ID, exact `prepared_digest`, consent/obligation
   proofs, commit nonce, expected reservation version, and client audit receipt.
4. `OP_RESULT`: final status, preparation/commit/idempotency IDs, result or
   encrypted blob reference, output schema digest/classification, effect receipt,
   new resource version, resource/cost usage, audit receipt, and rollback token
   if supported.

The server atomically marks a preparation `COMMITTED` before or with the effect.
Repeated identical commits return the same result receipt; a different commit
for that preparation is `COMMIT_MISMATCH`. An expired preparation has no effect.

- `OP_CANCEL` targets a request/preparation/operation/stream, gives a reason and
  expected state. Cancellation is best effort after an irreversible commit and
  returns the authoritative state.
- `OP_STATUS` returns `unknown`, `preparing`, `prepared`, `committing`,
  `succeeded`, `failed`, `cancelled`, `expired`, or `in_doubt`, plus the last
  signed receipt. `unknown` must not cause an automatic retry of a non-idempotent
  operation; recovery follows Section 28.8.

### 18.7 Streams and subscriptions (96–114)

`STREAM_OPEN` binds a stream ID to parent operation, direction, content schema,
classification, total-size/chunk limits, initial credit, optional total digest,
and expiry. `STREAM_DATA` carries stream ID, offset, chunk sequence, bytes or
typed items, chunk digest, and end flag. `STREAM_CREDIT` grants additional bytes
and messages with an absolute ceiling. `STREAM_CLOSE` carries final size/count,
ordered-stream digest, status, and audit reference.

Data outside credit, gaps/overlap, digest mismatch, reuse of a stream ID, or data
after close is fatal to that stream. Stream chunks remain individually signed.
A registered batch-signature extension may sign a bounded Merkle root only if
each leaf commits stream/session/direction/offset/chunk bytes and no chunk is
released to an effectful consumer before its proof verifies.

`SUBSCRIBE` contains event classes, resource selectors, start checkpoint,
filters, expiry, maximum rate, and credit. Each `EVENT` contains subscription ID,
event sequence, source checkpoint, event type/body, and redaction metadata.
`UNSUBSCRIBE` is final and idempotent. Subscription authorization is rechecked
on policy/capability/revocation change and at least every five minutes.

### 18.8 Manifests, registry, and audit (128–147)

- `MANIFEST_GET/RESULT`: exact tool ID/version or digest query; result contains
  immutable manifest bytes, publisher signature, status, TUF metadata/proofs,
  transparency proof/promise, and expiry.
- `REGISTRY_QUERY/RESULT`: Section 17 query, object/proof array, and bound cursor.
- `AUDIT_SUBMIT`: ordered signed events, emitter range, prior checkpoint, and
  maximum merge delay.
- `AUDIT_RECEIPT`: accepted/rejected event digests, signed inclusion promise,
  log ID, tree-size expectation, merge deadline, and witness policy.
- `AUDIT_PROOF_REQUEST`: log ID, event/leaf digest or tree sizes, nonce.
- `AUDIT_PROOF`: inclusion/consistency proof, signed tree head, witness
  signatures, and nonce.

### 18.9 Error message (255)

`ERROR` contains error code, safe title, retry class, related message/request ID,
failed protocol state, optional minimum retry time, required profile/extension,
and a random support correlation ID. It MUST NOT contain stack traces, secret
values, credentials, capability bodies, policy source, raw prompts, internal
hostnames, or distinguish unauthorized from nonexistent sensitive resources.

## 19. Wire Format

The native wire object is `COSE_Sign1` (CBOR tag 18) whose payload is one
deterministically encoded SMCP envelope. The protected header contains:

- COSE `alg` and `kid`;
- non-empty `crit` containing every SMCP private protected-header label and every
  security-critical extension header;
- private-use draft labels for `smcp-version`, `smcp-type`, `smcp-session`,
  `smcp-seq`, and the literal domain separator `SMCP/1`.

The protected version/type/session/sequence values duplicate the envelope and
MUST compare equal. This enables dispatch without trusting unsigned data while
keeping signed application semantics visible. The unprotected COSE map MUST be
empty in Core; otherwise intermediaries could influence interpretation.

The COSE Sig_structure external AAD is:

```cddl
external_aad = [
  "SMCP-EXTERNAL-AAD-v1",
  transport_profile_id,
  channel_binding / null,
  negotiation_transcript_hash
]
```

For established TLS sessions, `channel_binding` is the 32-byte TLS exporter in
Section 7.4. For store-and-forward E2E records it is null and the recipient,
expiry, replay epoch, and HPKE context are signed in the envelope. A record
cannot be copied between these modes because `transport_profile_id` differs.

During the handshake, `negotiation_transcript_hash` is the rolling
`SHA-256("SMCP-TRANSCRIPT-v1" || exact_prior_handshake_records)` in the total
order in Section 18.2; the initial `CLIENT_HELLO` therefore uses the
domain-separated empty prefix. The current record is appended only after it
verifies, avoiding a circular signature input. `SERVER_HELLO.transcript_hash`
and `AUTH_RESULT.transcript_hash` commit to the prior rolling hash and the
current canonical body with that commitment field omitted. Omitting only the
commitment field prevents a self-referential hash while binding every other
body field before the record is signed.
After both FINISH records, every established-session record uses the fixed final
transcript hash. A relay profile replaces it with the recipient security-context
hash specified by that profile and signed inside the HPKE-protected envelope.

### 19.1 Framing and limits

Reliable byte streams use a 4-byte unsigned network-order length followed by one
complete COSE object. Zero length, lengths above the negotiated maximum, and
trailing bytes are protocol errors. Core defaults: record 1 MiB, handshake
64 KiB, nesting depth 16, map entries 256, array entries 4096, text 64 KiB, and
capability chain 8. Larger data uses streams/blobs with digest binding.

Receivers read the length, reserve only bounded memory, parse once, verify
protected routing fields and signature, then decode the body. They MUST NOT
perform business side effects or dereference attacker-controlled URIs before
signature, freshness, audience, schema, and authorization checks.

### 19.2 End-to-end relay protection

Where transport terminates at a relay, the signed COSE object is additionally
encrypted to the final recipient using an RFC 9180 HPKE registered suite. The
relay header contains only recipient routing key ID, bounded expiry, ciphertext
length, and message commitment and is itself sender-signed. Core recipients
support HPKE base mode with authenticated sender identity supplied by the inner
signature; auth mode MAY be profiled. Forward-secure multi-party group messaging
uses an MLS profile, not a custom group cipher.

### 19.3 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | JSON ambiguity, unsigned routing, proxy termination, and unbounded parsers create tampering and DoS risk. |
| Design | Deterministic CBOR in COSE_Sign1, empty unprotected headers, transcript/channel external AAD, bounded framing, optional standard HPKE. |
| Alternatives | JSON/JWS, Protobuf plus ad hoc signatures, HTTP Message Signatures. |
| Tradeoffs | Binary diagnostic cost; compact exact bytes and transport independence. JSON/JCS remains a diagnostic profile, not native Core signing. |
| Security | Determinism removes alternate encodings; signatures do not hide metadata, so HPKE is required across untrusted relays. |
| Performance | Compact encoding and single-pass bounded decode; one signature per record. |
| Compatibility | COSE/CBOR libraries are broadly available; gateways can expose JSON but must preserve/verify original COSE. |
| Extensibility | Integer registries and critical protected headers allow additive fields safely. |

## 20. Transport Layer

All transports provide confidentiality, integrity, peer authentication,
forward secrecy, ordered reliable delivery per record stream, exporter/channel
binding where defined, and explicit maximum sizes. Cleartext TCP, HTTP, stdio,
WebSocket, message queues, and local sockets are not conformant Core transports.

### 20.1 Required profiles

| Profile | Requirement |
|---|---|
| `smcp-tls13` | TLS 1.3 over a reliable byte stream with ALPN `smcp/1`, mutual application identity, Section 19 length framing, and post-handshake record signatures. TLS 1.2 and renegotiation are forbidden. |
| `smcp-h3` | QUIC v1 with TLS 1.3 and HTTP/3. `CONNECT` establishes a bidirectional SMCP session using media type `application/smcp+cbor`; each direction preserves record order. QUIC migration triggers policy and channel-binding revalidation. |
| `smcp-local` | Private Unix-domain socket, Windows named pipe, or loopback connection carrying TLS 1.3 `smcp/1`; OS peer credentials and private ACLs are additional evidence, never replacements for identity/signatures. |
| `smcp-relay-hpke` | Any registered durable broker transport with inner signed+HPKE-encrypted records, recipient acknowledgements, durable replay state, ordering key, and expiry enforcement. Broker TLS remains mandatory. |

HTTP/2 MAY be registered with extended CONNECT and the same semantics. Ordinary
HTTP POST request/response is a gateway mapping, not a full duplex Core session,
unless its profile specifies ordering, channel binding, close, and streams.

### 20.2 TLS requirements

Implementations support TLS 1.3 RFC 8446, validate endpoint name/application
identity and status, use registered AEAD cipher suites, disable unauthenticated
resumption across identity/policy changes, and bind PSK tickets to service,
trust-domain, credential assurance, and policy epoch. Mutations, capability
issuance/delegation/revocation, consent, trust changes, registry publication, and
audit administration MUST NOT use 0-RTT. A profile may allow 0-RTT only for an
explicit idempotent public bootstrap request with server replay defense; Core
clients default it off.

TLS compression is forbidden. Connection coalescing is permitted only when the
authenticated SMCP service principal and audience are identical, not merely
because a certificate covers both DNS names.

### 20.3 Noise profile

A future constrained/local profile may register an unmodified Noise Protocol
Framework handshake pattern and standard cipher suite. It must specify identity
key binding, transcript-to-SMCP external AAD, negotiation/downgrade behavior,
rekey, credential validation, test vectors, and formal analysis. Generic
“Noise support” is not negotiable, and Noise does not replace signed records.

### 20.4 Decision record

| Dimension | Decision |
|---|---|
| Problem/threat | Transport independence can become permission to run insecure plaintext or lose identity/channel semantics. |
| Design | A transport contract with TLS 1.3/QUIC mandatory profiles and signed records above it. |
| Alternatives | HTTPS only; custom encryption; Noise-only; application signatures without encryption. |
| Tradeoffs | More constrained than arbitrary MCP transports; consistent confidentiality and binding across production environments. |
| Security | TLS protects hops and metadata on each hop; inner HPKE protects across relays. Endpoint compromise and traffic analysis remain. |
| Performance | QUIC reduces setup/head-of-line costs; TLS framing is simple; HPKE adds per-recipient encapsulation. |
| Compatibility | Fits existing PKI, proxies, service meshes, and QUIC stacks; local adapters use normal OS IPC plus TLS. |
| Extensibility | A transport must pass the conformance contract before registry allocation. |

## 21. Encoding Formats

Deterministic CBOR (RFC 8949 Section 4.2) is the REQUIRED native encoding.
Security objects use integer map keys from `registries.md`, shortest integer and
length forms, definite lengths, sorted keys, valid shortest UTF-8, and no
duplicate keys. Floating point, NaN, Infinity, shared references, and
self-described-CBOR tags are forbidden in security structures. Application
schemas may register decimal fractions or floats with one canonical form; money
uses integer minor units plus currency.

JSON is OPTIONAL for diagnostics and administrative import/export. A JSON
profile uses UTF-8 I-JSON, RFC 8785 JCS, base64url without padding for byte
strings, decimal strings outside the interoperable integer range, and an
explicit CBOR-key mapping. Native signatures are never verified over a JSON
re-serialization; the original COSE bytes travel with diagnostic JSON. A future
JWS/JCS profile requires separate vectors and cannot be silently substituted.

### 21.1 Compression negotiation

`none` is REQUIRED and default. `zstd-rfc8878` is OPTIONAL and may be selected
only per body/stream when:

- no secret, credential, capability, consent authenticator, or private cross-
  tenant value shares a compression context with attacker-controlled data;
- the decompressed size and ratio are declared and bounded;
- dictionaries are immutable, signed, digest-bound, non-secret, and selected
  before data processing;
- compression occurs before encryption and after authorization to send; and
- contexts are reset per message/security origin.

Compression of handshake/authentication/authorization/audit-control records is
forbidden. Unknown compression is fatal, never treated as `none`.

## 22. Version Negotiation

Versions are `[major, minor]`. A major changes semantics or wire compatibility.
A minor is additive: existing required fields and invariants cannot be weakened,
and new mandatory behavior requires a new major or negotiated critical
extension.

The client offers an ordered list of exact versions and a signed `min_version`.
The server selects one offered supported version not below either party's local
security floor, and reports its `max_supported_version`. Both hellos and all
offered/selected algorithms, encodings, compression, transports, credential
profiles, extensions, and limits enter the transcript hash. Both FINISH records
confirm it. Selection outside the offer, stripping an offer, or contradicting
the transport's ALPN produces `NEGOTIATION_DOWNGRADE` and permanent connection
failure.

There is no retry with a lower version on the same endpoint after a downgrade
error. A client may connect to a separately configured legacy gateway only when
policy names that gateway and its reduced guarantees. Implementations advertise
deprecated versions until a signed sunset time but refuse them after the local
minimum moves forward.

Algorithm suites are registry IDs containing record signature, hash, transport
requirements, capability/manifest algorithms, and optional HPKE. Peers negotiate
a complete registered suite, not combinatorial arbitrary primitives. Core suite
`S1` uses SHA-256 and ES256; `S2` uses SHA-256 and Ed25519. FIPS profiles use
approved suite `S1-FIPS` and an approved TLS provider configuration.

## 23. Extension Framework

An extension has a stable URI, owner, specification URL/digest, version range,
status, wire keys/types, criticality, privacy/security analysis, required
permissions, error behavior, downgrade behavior, and conformance vectors.

Extensions appear in the signed envelope. If interpretation changes security,
authorization, effects, identity, consent, evidence, or parsing, its ID MUST be
listed in the protected `critical_extensions` array. A receiver that does not
understand an offered critical extension rejects negotiation; one that encounters
an unnegotiated critical extension closes with `EXTENSION_UNSUPPORTED`.
Noncritical extensions may add informational metadata only and cannot affect
whether or how an effect executes.

Extensions MUST NOT:

- disable signing, authentication, encryption, authorization, audit, freshness,
  audience, replay, or fail-closed behavior;
- reinterpret a Core key or registered action/resource;
- introduce unbounded recursive parsing or executable code in messages;
- turn content/model output into a security fact;
- allocate cryptographic algorithms outside the relevant standards registry.

Experimental extensions use organization-controlled URIs and are disabled in
interoperability/compliance profiles unless explicitly named. Promotion requires
two independent implementations, security review, threat analysis, stable
vectors, and registry expert review.

## 24. Plugin API

The secure plugin model is out-of-process. A plugin is an SMCP service with its
own principal, signed manifest, capability set, sandbox, resource limits, and
audit stream. Loading arbitrary native code into the SMCP TCB is not the Core
plugin API.

### 24.1 Standard service provider interfaces

| SPI | Operations | Security rule |
|---|---|---|
| Credential Verifier | `verify`, `status`, `challenge` | Returns signed normalized facts; never a grant. |
| Capability Service | `issue`, `exchange`, `delegate`, `status`, `revoke` | Requires administrative capabilities; preserves attenuation. |
| PDP | `decide`, `explain_digest`, `bundle_status` | Input/output digest bound; timeout/error deny. |
| Risk Engine | `assess`, `factor_status` | Can only restrict/require/block. |
| Consent Provider | `request`, `verify`, `consume`, `revoke` | Trusted UI/authenticator boundary; atomic consumption. |
| Manifest/Registry | `publish`, `resolve`, `verify`, `status` | Original bytes and proof returned; ranking not trust. |
| Audit Provider | `append`, `receipt`, `proof`, `checkpoint` | Durable-before-effect modes and privacy labels. |
| Attestation Verifier | `challenge`, `appraise`, `reference_status` | RATS roles kept explicit; signed appraisal. |
| Transport Adapter | `listen`, `connect`, `export_binding`, `limits` | Must satisfy Section 20; never exposes plaintext records. |
| Encoding Adapter | `validate`, `encode`, `decode` | Deterministic, bounded, differential-tested. |

Every invocation is capability-restricted and declares whether data may leave
the local trust domain. Providers cannot return unsigned security decisions.
Provider discovery pins manifest and principal. Updates use the supply-chain
rules of Section 15. A provider crash yields fail-closed behavior; circuit
breakers may preserve availability only for operations whose policy names a safe
cached fact and validity interval.

An in-process implementation may link a provider only when it is part of the
declared TCB, signed as one artifact, has no broader permissions than required,
and passes the same behavioral conformance suite. It is not called a third-party
plugin.

## 25. Error Codes

Error code is a 32-bit unsigned integer: high 12 bits facility, low 20 bits
reason. The initial codes below are stable. Retry classes are `never`,
`same-message` (only when explicitly safe), `new-message`, `after-reauth`, and
`after-administrator`.

| Hex | Name | Retry | Meaning / receiver action |
|---:|---|---|---|
| `0x00100001` | `MALFORMED_RECORD` | never | Framing/CBOR/COSE invalid; close after rate-safe audit. |
| `0x00100002` | `LIMIT_EXCEEDED` | new-message | Negotiated parser/message limit exceeded. |
| `0x00100003` | `DUPLICATE_KEY` | never | Ambiguous CBOR map; close. |
| `0x00100004` | `UNSUPPORTED_MESSAGE` | never | Type not negotiated/supported. |
| `0x00100005` | `WRONG_STATE` | never | Message illegal in current state; repeated violation closes. |
| `0x00200001` | `SIGNATURE_INVALID` | never | Record or object signature failed; no detail. |
| `0x00200002` | `KEY_UNKNOWN` | after-reauth | `kid` unavailable or outside active epoch. |
| `0x00200003` | `AUDIENCE_MISMATCH` | never | Receiver not exact audience. |
| `0x00200004` | `MESSAGE_EXPIRED` | new-message | Fresh message required. |
| `0x00200005` | `REPLAY_DETECTED` | never | ID/sequence/nonce already accepted. |
| `0x00200006` | `SEQUENCE_GAP` | new-message | Ordered transport gap; resynchronize or close. |
| `0x00200007` | `CHANNEL_BINDING_FAILED` | never | Record transplanted/wrong channel. |
| `0x00300001` | `NEGOTIATION_NO_COMMON` | never | No allowed common version/suite/profile. |
| `0x00300002` | `NEGOTIATION_DOWNGRADE` | never | Transcript/offer/ALPN inconsistency; close and alert. |
| `0x00300003` | `EXTENSION_UNSUPPORTED` | never | Unknown required critical extension. |
| `0x00300004` | `COMPRESSION_FORBIDDEN` | new-message | Payload/context may not be compressed. |
| `0x00400001` | `AUTHENTICATION_FAILED` | after-reauth | Uniform credential/proof failure. |
| `0x00400002` | `IDENTITY_SUSPENDED` | after-administrator | Principal status blocks use. |
| `0x00400003` | `CREDENTIAL_EXPIRED` | after-reauth | Fresh credential required. |
| `0x00400004` | `ATTESTATION_REQUIRED` | after-reauth | Fresh registered evidence required. |
| `0x00500001` | `CAPABILITY_MISSING` | new-message | No authority presented. |
| `0x00500002` | `CAPABILITY_INVALID` | never | Signature/claims/chain invalid. |
| `0x00500003` | `CAPABILITY_EXPIRED` | new-message | New grant required. |
| `0x00500004` | `CAPABILITY_REVOKED` | after-administrator | Token/ancestor/key/epoch revoked. |
| `0x00500005` | `CAPABILITY_SCOPE` | new-message | Action/resource/constraint mismatch. |
| `0x00500006` | `CAPABILITY_REFERENCE_UNKNOWN` | new-message | Send full verified chain. |
| `0x00500007` | `DELEGATION_AMPLIFICATION` | never | Child is not provably a subset. |
| `0x00500008` | `QUOTA_EXHAUSTED` | after-administrator | Grant quota unavailable. |
| `0x00600001` | `POLICY_DENIED` | after-administrator | Uniform deny; does not reveal resource existence. |
| `0x00600002` | `POLICY_INDETERMINATE` | new-message | PDP/fact failure; PEP denied. |
| `0x00600003` | `OBLIGATION_UNSATISFIED` | new-message | Named safe obligation proof absent. |
| `0x00600004` | `RISK_BLOCKED` | after-administrator | Current signed assessment blocks. |
| `0x00700001` | `CONSENT_REQUIRED` | new-message | Use attached consent request digest. |
| `0x00700002` | `CONSENT_DENIED` | after-administrator | Authority denied; do not reprompt automatically. |
| `0x00700003` | `CONSENT_INVALID` | new-message | Receipt mismatch, consumed, expired, or revoked. |
| `0x00800001` | `MANIFEST_REQUIRED` | new-message | Exact verified manifest absent. |
| `0x00800002` | `MANIFEST_INVALID` | after-administrator | Signature/schema/provenance/trust failure. |
| `0x00800003` | `ARTIFACT_MISMATCH` | after-administrator | Executed bytes differ from manifest. |
| `0x00900001` | `PREPARE_CONFLICT` | new-message | Resource/version/quota cannot be reserved. |
| `0x00900002` | `PREPARATION_EXPIRED` | new-message | Prepare again and obtain new consent if required. |
| `0x00900003` | `COMMIT_MISMATCH` | never | Commit does not match prepared digest/nonce. |
| `0x00900004` | `OPERATION_IN_DOUBT` | same-message | Query status; do not repeat effect. |
| `0x00900005` | `CANCEL_TOO_LATE` | never | Effect is committed/irreversible; inspect receipt. |
| `0x00A00001` | `STREAM_CREDIT_EXCEEDED` | never | Close stream; peer exceeded credit. |
| `0x00A00002` | `STREAM_INTEGRITY` | never | Chunk/order/final digest invalid. |
| `0x00B00001` | `REVOCATION_STATUS_STALE` | new-message | Obtain fresher authoritative proof. |
| `0x00B00002` | `REGISTRY_STALE` | new-message | Metadata/log/TUF freshness failed. |
| `0x00B00003` | `AUDIT_UNAVAILABLE` | new-message | Required durable append/receipt unavailable. |
| `0x00B00004` | `TRANSPARENCY_PROOF_INVALID` | after-administrator | Proof/checkpoint/witness validation failed. |
| `0x00C00001` | `RATE_LIMITED` | new-message | Honor signed `retry_after`; no authority implication. |
| `0x00C00002` | `DEADLINE_EXCEEDED` | new-message | Operation not committed unless status says otherwise. |
| `0x00FFF001` | `INTERNAL_FAILURE` | new-message | Safe generic failure with support correlation ID. |

Unknown errors are handled by facility and retry class; they never default to
retrying a mutation. Authentication/authorization/not-found responses SHOULD be
indistinguishable in timing and public text where resource enumeration matters.

## 26. Compliance Profiles

All profiles include Core; they can strengthen but not weaken invariants.

| Profile | Mandatory additional requirements |
|---|---|
| `SMCP-CORE-1` | Deterministic CBOR/COSE, suite S1 and S2 verification (S1 signing required), TLS 1.3, PoP capabilities, Cedar semantics, signed audit, full negative conformance. |
| `SMCP-WEB-1` | HTTP/3 profile, WebPKI bootstrap, OAuth Security BCP, PKCE, PAR/resource indicators where applicable, exact issuer, no access-token pass-through, CSP/trusted consent UI. |
| `SMCP-WORKLOAD-1` | SPIFFE X.509-SVID and Workload API, federation bundles, short-lived automatic rotation, mTLS, workload isolation. |
| `SMCP-HUMAN-1` | OIDC identity mapping, WebAuthn Level 3-compatible transaction approval with UV, accessible trusted display, consent revocation. |
| `SMCP-SUPPLY-CHAIN-1` | TUF threshold roots/freshness, Sigstore bundle verification, in-toto provenance, SBOM policy, digest-pinned sandbox execution, transparency monitoring. |
| `SMCP-LOCAL-1` | Private ACL local endpoint plus TLS 1.3, OS peer credential evidence, no raw stdio, explicit install-time pin/bootstrap. |
| `SMCP-RELAY-1` | Inner HPKE, durable replay/ordering state, recipient delivery receipts, metadata minimization, relay-compromise tests. |
| `SMCP-HIGH-ASSURANCE-1` | HSM/TPM non-exportable keys, RATS/EAT freshness, S1-FIPS where required, dual control, no 0-RTT/compression, witnessed audit-before-effect, 60-second revocation status. |
| `SMCP-REGULATED-1` | HIGH-ASSURANCE plus purpose/data-region/retention policies, separation of duties, encrypted audit detail, independent witnesses, evidence export and deletion proofs. |
| `SMCP-CONSTRAINED-1` | Fixed registered suite, bounded CDDL subset, no JSON/compression/dynamic extensions, provisioned trust bundle, capability depth 2; security invariants unchanged. |

Conformance claims name exact protocol/profile versions, implementation build
digest, crypto provider/mode, operating environments, test-suite digest/date,
and exceptions. Partial conformance cannot use the profile name.

## 27. Reference State Machine

### 27.1 Connection/session states

```text
DISCONNECTED
  -> CHANNEL_SECURE
  -> NEGOTIATING
  -> AUTHENTICATING
  -> CONFIRMING
  -> ESTABLISHED
       <-> REAUTHENTICATING
       <-> REKEYING
  -> DRAINING
  -> CLOSED

Any non-recoverable violation -> FAILED -> CLOSED
```

| Current | Event/message | Guard | Next | Required action |
|---|---|---|---|---|
| `DISCONNECTED` | secure transport success | endpoint policy valid | `CHANNEL_SECURE` | Initialize transcript, limits, replay epoch. |
| `CHANNEL_SECURE` | send/receive `CLIENT_HELLO` | role and signature valid | `NEGOTIATING` | Record complete offered set. |
| `NEGOTIATING` | valid `SERVER_HELLO` | selections offered/allowed | `AUTHENTICATING` | Fix version/suite/limits/session ID. |
| `NEGOTIATING` | retry cookie | transcript restarts with same security floor | `CHANNEL_SECURE` | No identity/resource disclosure. |
| `AUTHENTICATING` | both `AUTHENTICATE`/`AUTH_RESULT` accepted | holder proof/status/attestation valid | `CONFIRMING` | Bind session keys and composite principals. |
| `CONFIRMING` | both `FINISH` valid | transcript/exporter agree | `ESTABLISHED` | Set sequence windows; allow authorized application traffic. |
| `ESTABLISHED` | `REAUTH` | challenge valid | `REAUTHENTICATING` | Pause actions requiring requested assurance. |
| `REAUTHENTICATING` | accepted auth + finish | new claims not weaker than active operation requirements | `ESTABLISHED` | Replace claims/epochs atomically. |
| `ESTABLISHED` | `REKEY` | current-key signature, future activation seq | `REKEYING` | Install overlap window. |
| `REKEYING` | activation acknowledged | sequence reached | `ESTABLISHED` | Erase old key after overlap. |
| `ESTABLISHED` | `CLOSE` or local drain | valid reason/deadline | `DRAINING` | Refuse new operations; finish/cancel existing by policy. |
| `DRAINING` | `CLOSE_ACK`/deadline | final receipts handled | `CLOSED` | Erase secrets; retain replay/audit metadata. |
| any live | fatal parse/signature/downgrade/binding error | — | `FAILED` | Minimal signed error if safe, audit, close without fallback. |

Application messages before `ESTABLISHED` are `WRONG_STATE`. Parallel messages
within a direction still use monotonically increasing record sequence; operation
ordering is expressed by IDs and state, not arrival race.

### 27.2 Operation states

```text
NEW -> VALIDATING -> PREPARED -> COMMITTING -> SUCCEEDED
                   |     |          |       -> FAILED
                   |     |          -> IN_DOUBT
                   |     -> CANCELLED/EXPIRED
                   -> REJECTED
```

| Current | Input | Atomic guard | Next / response |
|---|---|---|---|
| `NEW` | `OP_PREPARE` | unique idempotency key/body digest | `VALIDATING`; duplicates attach to same record. |
| `VALIDATING` | checks complete | allow intersection and reservation durable | `PREPARED` + receipt; otherwise `REJECTED`. |
| `PREPARED` | `OP_COMMIT` | digest, nonce, obligations, consent, epochs, version, deadline all exact | `COMMITTING`; consume consent/quota atomically. |
| `PREPARED` | cancel/deadline/security emergency | no commit accepted | `CANCELLED`/`EXPIRED`; release reservation. |
| `COMMITTING` | effect transaction commits | audit outbox durable | `SUCCEEDED` + immutable receipt. |
| `COMMITTING` | definitive rollback/failure | no effect or compensating state recorded | `FAILED` + receipt. |
| `COMMITTING` | outcome cannot be proven | no automatic retry | `IN_DOUBT`; reconciliation required. |
| terminal | identical retry | same request/prepared digest | Return identical signed terminal receipt. |
| any | mismatched reuse of ID/key | — | `COMMIT_MISMATCH`; audit and reject. |

### 27.3 Lifecycle coupling

- Trust degradation/suspension triggers reauthorization and may pause sessions.
- Identity key revocation closes affected sessions and invalidates holder-bound
  capabilities.
- Capability revocation cancels uncommitted preparations and subscriptions.
- Consent revocation cancels uncommitted preparations using that receipt.
- Manifest/artifact revocation stops new calls, drains safe reads, and cancels
  effectful preparations.
- Policy emergency epoch invalidates preparations named by its scope.
- Audit-log failure blocks operations whose obligations require durability.

These transitions are serialized by the PEP's security epoch. Every preparation
contains that epoch; commit compares it atomically, eliminating a check/use gap.

## 28. Security Considerations

This entire specification is security-sensitive. This section consolidates
deployment rules and recovery behavior that cross subsystem boundaries.

### 28.1 Cryptographic algorithm policy

SMCP defines no primitive. Core uses SHA-256, COSE ES256 and EdDSA/Ed25519,
TLS 1.3 registered AEAD suites, HKDF as specified by those protocols, and HPKE
registered suites when relay encryption is used. AES-GCM and
ChaCha20-Poly1305 are selected only through their parent TLS/HPKE/COSE standard.
Raw RSA encryption, static Diffie-Hellman, ECB/CBC application encryption,
home-grown key derivation, unauthenticated encryption, and `alg=none` are
forbidden.

Implementations MUST use a cryptographically secure random generator, perform
documented provider self-tests, keep long-term and high-value issuer keys in an
HSM/TPM/KMS appropriate to profile, zeroize ephemeral private keys where the
platform permits, and separate keys by purpose (identity, record, capability,
manifest, policy, audit, transparency, encryption, recovery). One key ID cannot
be used for incompatible purposes.

Algorithm deprecation is a signed Trust Bundle policy with minimum version,
not-before enforcement time, verification grace for historical evidence, and
replacement suite. Verification of archived signatures may retain a deprecated
algorithm in an isolated verifier; creating new signatures with it stops at the
enforcement time. Quantum-resistant migration requires standardized algorithms,
COSE/HPKE allocations, hybrid combiner analysis, and a new suite/profile; SMCP
does not invent a hybrid construction.

### 28.2 Key compromise

On suspected compromise, an operator MUST:

1. suspend the principal/key and stop new sessions;
2. publish signed revocation through independent authorized recovery keys and
   advance the issuer revocation epoch;
3. terminate sessions and invalidate holder-bound capabilities/preparations;
4. preserve and checkpoint audit evidence;
5. rotate dependent trust bundles, capabilities, tickets, pins, and encrypted
   audit data keys according to exposure;
6. re-enroll with threshold recovery, never continuity signed only by the
   compromised key; and
7. issue a signed incident/replacement statement without leaking sensitive
   incident details.

Historical events before the effective compromise time remain verifiable but
are marked with the incident interval. Determining which signatures an attacker
created before revocation is an investigation, not something cryptography can
solve retroactively.

### 28.3 Prompt and content isolation

All untrusted text and binary content carries origin principal, source URI,
acquisition message/event digest, timestamp, content type, integrity digest,
classification, and taint labels. Transformation creates a new provenance node
linked to its inputs. Security parsers never interpret instructions inside
content. Tools receive data and control on separate typed fields. A model may
recommend an action, but a deterministic operation builder normalizes it against
the signed schema and the PEP independently supplies identity/capability/policy.

Rendering MUST isolate untrusted HTML/Markdown/script, prohibit content from
imitating trusted consent UI, and display canonical destinations from signed
fields. Retrieval and browser adapters enforce origin-aware egress and prevent
credential/capability values from entering model context.

### 28.4 Confused-deputy and SSRF prevention

The audience, resource owner, canonical resource, destination origin/IP class,
HTTP method, redirect policy, DNS resolution policy, and permitted data classes
are bound into authority and preparation. Redirects are new resources and need
authorization; credentials are never forwarded across origins. Private,
loopback, link-local, metadata-service, and newly resolved addresses are denied
unless explicitly authorized. DNS is resolved at preparation and rechecked or
pinned at connect to prevent rebinding. HTTP callbacks use registered endpoint
metadata and sender-constrained credentials.

### 28.5 Parser, resource, and side-channel safety

Implementations enforce Section 19 limits before allocation; avoid recursive
descent beyond negotiated depth; reject duplicate/unknown critical fields; use
constant-time crypto comparisons; normalize once; and never resolve external
references during parsing. Per-principal/session/action quotas cover connections,
handshakes, verification CPU, requests, streams, bytes, log volume, consent
prompts, registry queries, and error replies. Backpressure is explicit via
credit; unlimited queues are forbidden.

Authentication and sensitive discovery errors are padded/bucketed where policy
requires enumeration resistance. Traffic volume, timing, recipient, and length
can still leak; the relay profile may add registered padding, but SMCP is not an
anonymity protocol.

### 28.6 Privacy

Data minimization applies to credentials, discovery, manifests, risk factors,
consent, and audit. Pairwise human identifiers SHOULD be used across unrelated
audiences. Correlation IDs are local to a workflow and not reused as global user
IDs. Selective-disclosure credentials may be added only as standardized
credential profiles with verifier unlinkability analysis; custom zero-knowledge
schemes are forbidden.

Every schema field has a privacy class, purpose, recipient, retention, and log
rule. Authorization to read data does not automatically authorize sending it to
a model provider, tool, registry, risk engine, or audit store. Egress is a
separate action and resource.

### 28.7 Time and freshness

Clock synchronization uses authenticated infrastructure; high-assurance profiles
use a trusted time source or signed freshness service. NTP without authentication
is not a security source. Large backward/forward jumps suspend time-dependent
authority. Nonces prove interaction freshness but do not establish calendar
time. Revocation, TUF, transparency, credential, and attestation objects each
carry independent next-update/expiry bounds; one fresh object cannot refresh
another.

### 28.8 Crash recovery and in-doubt effects

The authoritative operation journal stores idempotency key, request/prepared/
commit digests, reservation, state, effect transaction ID, and signed receipt.
After restart, the service reconstructs terminal results and never re-executes a
commit solely because the caller retries. If an external system cannot atomically
couple effect and journal, the adapter must use that system's idempotency/
conditional transaction, serialize the resource, or declare `non_atomic=true`.
High-assurance policy rejects non-atomic irreversible operations.

For `IN_DOUBT`, the client queries `OP_STATUS` using the same capability or a
narrow status capability. Only authoritative reconciliation moves the state to
succeeded/failed; a timeout does not. Compensation is a new authorized,
consented, audited operation—not silent rollback.

### 28.9 Revocation lifecycle

`VALID -> SUSPENDED -> REVOKED` or `VALID -> EXPIRED`. Signed status publications
are append-only by `(issuer, epoch, sequence)`. Mirrors cannot decrease epoch or
sequence. Emergency revocation is pushed over authenticated subscriptions and
confirmed through the authoritative status proof. A peer that cannot meet the
maximum staleness blocks affected actions. Recovery advances epochs and creates
new identifiers/keys as required; revoked tokens never become valid again.

### 28.10 Security decision summary

| Choice | Benefit | Cost / limitation | Compatibility and future path |
|---|---|---|---|
| Message signatures above TLS | End-to-end record attribution and relay/storage verification. | CPU/bytes; endpoint signer can still lie. | COSE now; registered post-quantum suites later. |
| PoP capabilities | Stops bearer replay and constrains deputy authority. | Key-bound issuance/cache complexity. | CWT/OAuth exchange bridge. |
| Two-phase side effects | Exact consent and TOCTOU resistance. | Extra round trip/reservation state. | Single phase retained for strict reads. |
| Typed policy outside model | Deterministic least privilege. | Policy engineering required. | Cedar/AuthZEN adapters. |
| Signed manifests/provenance | Exact artifact/effect binding. | Publisher/build infrastructure. | TUF/Sigstore/in-toto/OCI ecosystem. |
| Transparency audit | Independent tamper/equivocation detection. | Witness/log operation and metadata privacy. | RFC 9162 proof patterns; multiple logs. |
| Fail closed | Prevents missing security services becoming grants. | Availability loss during outages. | Carefully bounded cached facts and break-glass profile. |

### 28.11 Break-glass

Break-glass is not an error bypass. A deployment may define a separately signed,
short-lived emergency capability requiring threshold human approval, hardware
authentication, named actions/resources, maximum effects, local presence or
attestation, witnessed audit-before-effect, and automatic notification. It cannot
disable message signatures, encryption, attribution, or audit. Use advances an
emergency epoch and triggers mandatory review/revocation.

## 29. Implementation Guidelines

### 29.1 Processing pipeline

A receiver should implement immutable stages:

```text
bounded framing -> deterministic decode -> COSE/protected checks ->
session/replay/freshness/audience -> credential/status -> capability chain ->
manifest/artifact/runtime -> normalize operation -> PDP/risk/consent ->
reserve -> audit intent -> commit effect -> audit/result receipt
```

Later stages consume typed results, not raw attacker input. Validation errors
carry safe codes; caught exceptions are logged with local protected diagnostics,
not returned. Crypto providers expose typed keys and algorithms so callers
cannot pass algorithm names from messages directly into generic primitives.

### 29.2 Key and secret handling

- Prefer non-exportable long-term keys and short-lived session keys.
- Never place private keys, refresh tokens, raw capabilities, or consent
  authenticator data in environment variables, command lines, prompts, traces,
  crash dumps, metrics labels, or audit events.
- Pin issuer and audience; validate the whole chain and intended key use.
- Make test/dev trust roots visually and cryptographically distinct from
  production; production refuses them.
- Rotate automatically before 50% of credential lifetime and reauthenticate on
  relevant trust/policy epoch changes.

### 29.3 Concurrency and storage

Use one durable uniqueness constraint for `(resource_owner, idempotency_key)` and
store its request digest. Use transactions/compare-and-swap for preparation,
consent/quota consumption, security-epoch comparison, effect, and audit outbox.
Replay windows are per sender key/session and persist for relay/offline modes.
Do not use wall-clock ordering as a substitute for sequence or transaction IDs.

### 29.4 User experience

Trusted UI distinguishes verified principal ID, publisher, destination, effect,
data classes, cost, reversibility, duration, and delegated actor chain. It does
not display model-generated summaries as authoritative. Repeated denied consent
requests are rate limited and do not condition users to approve. Accessibility
and localization preserve canonical values and security meaning.

### 29.5 Observability

Metrics use bounded labels and aggregate codes; principal/resource/message IDs
are not raw high-cardinality labels. Traces carry opaque local references rather
than credentials or payload. Security events and application logs are separate.
Health endpoints reveal no identities, manifests, or policy detail without
authorization.

### 29.6 Compatibility adapters

Adapters terminate their source protocol, create a new SMCP record under their
own principal, attach `source_protocol`, `source_authenticated_as`, and
`assurance_limit`, and preserve the original bytes/digest as evidence when
permitted. They never assert that a source message had properties the source
protocol did not provide. Translation is schema-driven and rejects lossy
security-critical mappings.

## 30. Reference SDK Architecture

The reference architecture uses a small memory-safe core, with language SDKs
providing idiomatic APIs without reimplementing cryptographic or authorization
semantics.

### 30.1 Components

| Component | Responsibility and boundary |
|---|---|
| `smcp-core` | State machines, invariants, typed IDs/times, limits, operation lifecycle; no networking/business logic. |
| `smcp-codec` | Deterministic CBOR/CDDL validation, COSE construction, negative parser corpus. |
| `smcp-crypto` | Provider-neutral approved suites, key-purpose types, HSM/TPM/KMS adapters, zeroization. |
| `smcp-identity` | Credential profiles, trust bundles/federation, session binding, status/recovery. |
| `smcp-capability` | CWT/COSE claims, constraint implication, chains, quota/revocation. |
| `smcp-authz` | Cedar profile, AuthZEN client/server, immutable input and decision receipts. |
| `smcp-consent` | Request/receipt validation, WebAuthn bridge, atomic use store. |
| `smcp-risk` | Typed factors/outcomes and provider interface; no grant API. |
| `smcp-manifest` | Tool schema/effect/provenance/TUF/Sigstore/in-toto verification. |
| `smcp-session` | Handshake/transcript, replay/sequence, reauth/rekey/close. |
| `smcp-transport` | TLS 1.3, QUIC/H3, local and relay contract, channel exporter. |
| `smcp-operation` | Prepare/commit/idempotency/stream/subscription engines. |
| `smcp-audit` | Event construction, outbox, log client, proofs/witnesses/export. |
| `smcp-registry` | Signed publication/query, immutable cache, federation/freshness. |
| `smcp-policy-lint` | Static policy/manifest/capability analysis and simulations. |

Rust is RECOMMENDED for the reference core because it offers memory safety and
portable C ABI/WASM options. Native Rust, Go, Java, TypeScript, and Python SDKs
share canonical test vectors; bindings call the verified core for encoding,
signature-input construction, constraint logic, and state transitions. Pure
language implementations are conformant only if they pass the same suite.

### 30.2 Public API shape

SDKs expose high-level safe operations: `connect(identity, policy)`,
`discover(capability, filter)`, `prepare(operation)`, `satisfy(obligation)`,
`commit(prepared)`, `invoke_read(request)`, `open_stream`, `delegate`, and
`verify_receipt`. They do not expose “send unsigned map,” “skip verification,”
“accept any audience,” or “disable audit” APIs. Test-only insecure providers are
compile-time/build-feature isolated and cannot be linked into release artifacts.

### 30.3 Reference services

The project supplies a minimal trust-bundle/TUF server, capability STS,
AuthZEN-compatible PDP, consent service, registry, transparency log/witness,
and conformance peer. Reference services demonstrate semantics; production
operators may replace each through the signed provider interfaces.

## 31. Repository Structure

The standards and implementation repository should use:

```text
smcp/
  spec/
    draft-smcp-core.md
    draft-smcp-identity.md
    draft-smcp-capabilities.md
    draft-smcp-consent.md
    draft-smcp-tool-manifest.md
    draft-smcp-audit.md
    references.md
  schemas/
    smcp-v1.cddl
    policy-entities.cedarschema
    registry-metadata.cddl
  registries/
    message-types.csv
    errors.csv
    extensions.csv
    profiles.csv
    algorithms.csv
    actions.csv
    constraints.csv
  vectors/
    valid/
    invalid/
    canonicalization/
    crypto/
    state-machine/
  conformance/
    runner/
    assertions/
    reports/
  formal/
    tla/
    tamarin/
    pro-verif/
  reference/
    rust/
    services/
    cli/
  sdk/
    python/
    typescript/
    go/
    java/
  interop/
    compose/
    matrix/
    captures/
  security/
    threat-model.md
    disclosure.md
    audits/
  migrations/
    mcp-gateway.md
  governance/
    charter.md
    registry-policy.md
    change-control.md
```

Generated code and vectors identify source schema digest and generator build.
No generated file is the sole normative source. Changes to schemas, registries,
or invariants require spec text, vectors, conformance assertions, migration note,
and two-reviewer security approval in one change set.

## 32. Testing Strategy

Testing is layered and adversarial:

1. unit tests for deterministic encoding, constraints, state transitions, and
   every validation/error branch;
2. property tests for round-trip, canonical uniqueness, attenuation, replay,
   idempotency, and limit monotonicity;
3. protocol scenario tests for all roles/lifecycles and crash points;
4. security negative tests for every Section 4 threat and invariant;
5. differential tests across independent CBOR/COSE/TLS/policy implementations;
6. integration tests with HSM/TPM, SPIFFE, OIDC/WebAuthn, TUF, Sigstore, RATS,
   registries/logs, QUIC, proxies, and service meshes;
7. formal state/protocol models for authorization safety, transcript agreement,
   replay, delegation monotonicity, unique commit, revocation, and log consistency;
8. performance/soak/chaos tests with bounded resource assertions.

Every normative MUST has an assertion ID. Release requires all applicable
assertions, 100% transition/error coverage in the reference state machine,
branch coverage for validation code, no new unreviewed suppression, memory/
thread sanitizers where available, dependency/provenance verification, and a
reproducible signed build.

The test oracle never relies only on “both implementations agree”; it uses
normative expected bytes, state, error, audit event, and side-effect count.

## 33. Conformance Test Suite

### 33.1 Test protocol

A black-box runner operates as initiator, responder, malicious peer, registry,
PDP, consent provider, relay, and audit log. It records encrypted captures only
in isolated CI, validates signed receipts, and checks that forbidden effects did
not occur using instrumented resources. Each report binds implementation digest,
profile, configuration, vector-suite digest, platform, crypto provider, and time.

### 33.2 Mandatory assertion groups

| Group | Required assertions |
|---|---|
| `ENC` | Exact deterministic bytes; duplicate/out-of-order/non-shortest keys rejected; depth/size/UTF-8 limits. |
| `SIG` | Every type signed; protected/envelope equality; wrong alg/kid/AAD/audience/body rejected. |
| `NEG` | Offer stripping/selection injection/ALPN mismatch/fallback/unknown critical extension rejected. |
| `AUTHN` | Valid credential profiles; wrong issuer/audience/key use/status/proof/attestation freshness rejected. |
| `REPLAY` | Reused message ID, sequence, nonce, session, early data, relay redelivery, reboot state tested. |
| `CAP` | PoP, exact target, every claim, chain/depth, all attenuation dimensions, ancestor revocation and quota race. |
| `POL` | Default/error deny, forbid override, immutable input/policy digest, unknown fact/function and budget timeout. |
| `CONS` | Transaction/display digest, actor/resource/arg/effect swap, expiry/use/revocation, WebAuthn challenge/UV and concurrent consume. |
| `RISK` | Cannot grant, unknown factor handling, input binding, expiry and required-control enforcement. |
| `MAN` | Artifact/schema/effect/SBOM/provenance/TUF/log binding, rollback/freeze/mix-and-match, revoked publisher/tool. |
| `OP` | Prepare/commit mismatch, TOCTOU, deadline, crash at every durable boundary, duplicate concurrent commit, in-doubt recovery. |
| `STR` | Credit, ordering, gaps/overlap, final digest, classification/authorization recheck, cancellation. |
| `AUD` | Before-effect durability, hash chain, inclusion/consistency, split-view witness, redaction/no-secret leakage. |
| `DOS` | Oversize, deep nesting, floods, slow peer, signature exhaustion, decompression bomb, bounded queues. |
| `MIG` | Legacy gateway provenance limits and downgrade labeling. |

Tests that merely inspect an error are insufficient for effectful cases: the
runner asserts the backing resource, quota, consent counter, journal, and audit
state. Invalid vectors include one minimal mutation per protected field and
multi-fault inputs to prevent validation-order oracles.

### 33.3 Certification

At least two independent implementations must pass Core and claimed profile
tests against each other. A signed public result expires after 12 months or any
security-relevant implementation/configuration/schema change. Certification does
not replace deployment threat analysis or imply tool/model safety.

## 34. Fuzz Testing Strategy

Persistent coverage-guided fuzz targets include: length framer; CBOR scanner;
COSE protected-header parser; envelope dispatcher; every message body; CWT and
delegation-chain verifier; resource normalizers; Cedar entity/context adapter;
manifest/SBOM/provenance/TUF bundle parsers; HPKE relay envelope; Merkle proofs;
WebAuthn/EAT adapters; stream reassembler; and all state-machine event handlers.

Required fuzz modes:

- structure-aware CDDL generation and mutation;
- byte-level malformed CBOR/COSE, duplicate keys, integer boundaries, Unicode,
  tag confusion, deep nesting, truncation, trailing data, and length mismatch;
- cross-message stateful sequences with reorder/duplicate/drop/reconnect/rekey;
- differential decode/canonical encode across at least three libraries;
- cryptographic negative mutation without attempting to fuzz primitive internals;
- concurrency schedule exploration for prepare/commit/consent/quota/revocation;
- decompression bombs, dictionary confusion, and secret-context rejection;
- resource exhaustion with explicit CPU/allocation/queue/file-descriptor oracles.

Every crash, panic, hang, unbounded allocation, inconsistent result, accepted
noncanonical input, unauthorized effect, or secret in logs is a failure. The
corpus is minimized, versioned, public where non-sensitive, and promoted to a
permanent conformance vector. Fuzzers run under address, memory, thread, and
undefined-behavior sanitizers as applicable, plus deterministic allocation/time
budgets.

## 35. Interoperability Tests

The interop matrix crosses implementations, OS/architecture, TLS/QUIC stacks,
credential profiles, crypto providers, transport profiles, registries/logs,
PDPs, and version combinations. Required topologies are direct, reverse proxy,
service mesh, cross-SPIFFE federation, local IPC, HPKE relay, multi-registry
mirror, and disconnected-then-reconnected operation.

For each pair, test handshake, reauth/rekey, discovery, capability issue/
delegation/revocation, consent, read and two-phase effect, stream/backpressure,
cancellation, crash recovery, audit proof, graceful close, and every safe error
retry class. Captures compare semantic transcript hashes and canonical signed
bytes, not vendor log strings.

Compatibility rules:

- same major/different minor selects the highest exact mutually offered version;
- an older peer ignores only negotiated noncritical informational extensions;
- unknown critical behavior fails identically;
- JSON diagnostic output round-trips to the same embedded COSE bytes;
- profile-specific credentials produce the same normalized identity facts;
- Cedar/AuthZEN implementations produce equivalent result/obligation semantics
  for the standard corpus;
- gateway tests clearly lose origin signature/attestation where legacy lacks it.

An interop event publishes signed, reproducible reports and retains failing
captures as redacted vectors. Pairwise success is not declared from a happy-path
ping alone.

## 36. Migration Strategy from MCP

Migration uses an explicit SMCP–MCP Security Gateway. It is a new principal and
trust boundary, not a transparent proxy.

### 36.1 Mapping

| MCP concept | SMCP mapping | Security consequence |
|---|---|---|
| Client/server connection | Authenticated SMCP gateway session | Gateway authenticates legacy side using available transport/OS/OAuth facts and states assurance. |
| JSON-RPC request ID | Correlation/idempotency input | Never used as SMCP message ID or replay proof. |
| Tool name/description/schema | Provisional manifest namespace/action/schema | Effects/permissions are administratively supplied and marked `unverified-source`; no publisher provenance is fabricated. |
| OAuth token | Exchanged audience-specific PoP capability | Raw bearer token remains at gateway and is not forwarded. |
| Tool call | Read request or prepare/commit operation | Unknown/side-effectful calls default to two-phase, consent, sandbox, and strict egress. |
| Progress/notifications | SMCP event/stream | Credit, classification, authorization recheck, and signed origin become gateway properties. |
| MCP logging | Application diagnostic event | Does not become SMCP audit without gateway-signed audit construction and durability. |

The gateway's signed record contains source protocol/version, source endpoint,
authentication method and assurance, original message digest, mapping-policy
digest, synthesized fields, and `origin_signature=false` when applicable. The
gateway is accountable for validation/mapping; it cannot sign as the MCP client
or tool.

### 36.2 Deployment phases

1. **Inventory:** enumerate servers/tools/actions/data flows/auth, classify
   effects and owners, freeze unknown dynamic tools.
2. **Observe:** gateway creates shadow manifests and audit commitments without
   enforcing effects; compare actual permissions/egress to declarations.
3. **Constrain:** exchange tokens, require gateway identity, PoP capabilities,
   sandboxing, quotas, and deny undeclared egress.
4. **Govern effects:** enable prepare/commit and trusted consent for mutations;
   deploy policy and revocation.
5. **Provenance:** publishers ship signed native manifests/artifacts and
   supply-chain evidence.
6. **Native endpoints:** replace legacy hops with SMCP; keep gateway only for
   named exceptions with sunset dates.
7. **Disable downgrade:** remove legacy discovery/listeners/credentials and
   advance minimum trust policy.

Each phase has measurable exit criteria and a rollback that does not silently
restore broad authority. Legacy fallback uses a separately addressed endpoint,
visible assurance label, narrower capability, and audit event. There is never
automatic protocol downgrade.

### 36.3 Comparison and limits

MCP remains useful for tool/context interoperability and is evolving its own
authorization and security guidance. SMCP is stronger where a deployment needs
mandatory application signatures, compositional PoP authorization, effect-bound
consent, artifact provenance, two-phase operations, and verifiable audit across
non-HTTP transports. The gateway cannot manufacture end-to-end guarantees; full
benefit arrives only when both endpoints implement SMCP natively.

## 37. Future RFC Roadmap

Standardization is split so the stable security kernel does not wait for every
ecosystem profile.

| Track | Document | Dependency / graduation requirement |
|---:|---|---|
| 1 | Architecture, terminology, threat model, Core records and invariants | Formal security review; two independent Core implementations. |
| 2 | Deterministic CBOR/COSE wire format and IANA registries | Stable CDDL, canonical/negative vectors, COSE expert review. |
| 3 | TLS 1.3/QUIC/HTTP3/local transport profiles | Interop across three stacks; exporter/downgrade analysis. |
| 4 | Identity and federation profiles (SPIFFE, WebPKI, OIDC, WebAuthn) | Identity/privacy review; cross-domain tests; OAuth BCP alignment. |
| 5 | PoP capability, delegation, constraints, revocation | Formal monotonicity and replay analysis; STS interop. |
| 6 | Authorization, Cedar profile, AuthZEN binding, obligations | Policy corpus equivalence and deny/error proofs. |
| 7 | Consent and trusted transaction display | Human-factors/accessibility studies; WebAuthn/FIDO review. |
| 8 | Tool manifest, TUF/Sigstore/in-toto and sandbox profiles | Publisher/build/registry interop and incident exercises. |
| 9 | Audit transparency, privacy, witnesses and evidence export | Independent log implementations, split-view drills, privacy review. |
| 10 | RATS/EAT runtime attestation profile | Verifier interoperability and freshness/reference-value governance. |
| 11 | HPKE relay and MLS multi-agent group profile | Metadata/replay analysis and formal group-state review. |
| 12 | Constrained/IoT and approved post-quantum suites | Standardized algorithms only; measured performance and migration analysis. |
| 13 | MCP/HTTP/gRPC/Kubernetes gateways | Lossless-security mapping rules and explicit assurance taxonomy. |
| 14 | Compliance, conformance API, certification and registry governance | Open test suite, reproducible signed results, multi-stakeholder process. |

### 37.1 Governance and compatibility

The project uses an open charter, public issue/change history, disclosed conflicts
of interest, designated security response team, and multi-vendor review. Core
invariants require standards-track major revision. Registry allocations follow
Specification Required with expert security/privacy review; cryptographic
algorithms also require allocation/acceptance in their governing standards
registry. Vendor ranges cannot alter Core semantics.

Minor revisions are additive and ship with vectors before implementations claim
support. A major revision defines coexistence, bidirectional downgrade defense,
migration, deprecation dates, and archival verification. At least two independent
implementations and one adversarial interoperability event are required before a
draft is proposed for standards adoption.

### 37.2 References

The normative design relies on the following existing standards and profiles:

- BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html),
  [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html));
  [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html); QUIC
  ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html),
  [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html));
  [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html); and
  [TLS Exporters](https://www.rfc-editor.org/rfc/rfc5705.html).
- [CBOR](https://www.rfc-editor.org/rfc/rfc8949.html); COSE
  [Structures](https://www.rfc-editor.org/rfc/rfc9052.html) and
  [Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html);
  [CWT](https://www.rfc-editor.org/rfc/rfc8392.html) and
  [CWT confirmation](https://www.rfc-editor.org/rfc/rfc8747.html);
  [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html);
  [MLS](https://www.rfc-editor.org/rfc/rfc9420.html); and
  [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) for
  gateways.
- [OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
  [Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html),
  [Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html),
  [PAR](https://www.rfc-editor.org/rfc/rfc9126.html),
  [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html),
  [Authorization Details](https://www.rfc-editor.org/rfc/rfc9396.html),
  [Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html),
  [Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html),
  [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), and
  [WebAuthn](https://www.w3.org/TR/webauthn-3/).
- [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/);
  [RATS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html);
  [EAT](https://www.rfc-editor.org/rfc/rfc9711.html);
  [TUF](https://theupdateframework.org/spec/);
  [Sigstore bundles](https://docs.sigstore.dev/about/bundle/);
  [in-toto](https://in-toto.io/);
  [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) transparency proofs;
  [Cedar](https://docs.cedarpolicy.com/);
  [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html);
  and [CEL](https://github.com/google/cel-spec) where registered.
- [JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html),
  [I-JSON](https://www.rfc-editor.org/rfc/rfc7493.html), and
  [Zstandard](https://www.rfc-editor.org/rfc/rfc8878.html) for optional profiles.

Informative comparisons include HTTP/HTTPS, SSH, gRPC, Kubernetes security and
admission models, OAuth/OIDC deployment patterns, SPIFFE federation, and the
Model Context Protocol architecture/security guidance. Their useful mechanisms
are composed or profiled; none is claimed to provide all SMCP invariants alone.

---

## Appendix A. Protocol decision checklist

Every future normative change MUST document: problem; threat; design;
alternatives; tradeoffs; advantages; disadvantages; security analysis;
performance impact; compatibility impact; and future extensibility. It MUST add
or update CDDL, registries, valid/invalid vectors, conformance assertions,
formal-model properties where applicable, implementation guidance, and migration
text. A change without these artifacts is incomplete and cannot advance.

## Appendix B. Why implementations become simpler

SMCP moves recurring security choices into one protocol contract: canonical
bytes, signature input, identity binding, capability claims, authorization
input, consent receipt, two-phase effect, error taxonomy, audit event, lifecycle,
and downgrade rules. Application authors implement typed resources/effects and
policy; they do not design token forwarding, replay caches, consent text, log
integrity, or per-transport security anew. The protocol is more demanding than
an RPC envelope, but conformant implementations have fewer security degrees of
freedom and therefore fewer incompatible or accidentally unsafe modes.

## Appendix C. Cross-subsystem decision ledger

Earlier sections contain detailed records for architecture, signatures, trust,
identity, capability, authorization, delegation, consent, policy, risk, audit,
manifests, discovery, registry, wire format, and transport. This ledger records
the remaining normative design choices using the same required dimensions.

### C.1 Deterministic CBOR native encoding

- **Problem:** security objects need one compact representation across transports.
- **Threat:** JSON numeric, Unicode, and key ambiguity can make verification and
  execution interpret different objects.
- **Design:** RFC 8949 deterministic CBOR, closed CDDL, and exact-byte signatures;
  JSON/JCS is diagnostic and carries the original COSE.
- **Alternatives:** JSON/JWS, Protobuf, and ASN.1 DER.
- **Tradeoffs:** binary inspection is less convenient; canonical bytes, integer
  keys, streaming bounds, and COSE composition are direct.
- **Advantages:** compactness, deterministic vectors, and transport neutrality.
- **Disadvantages:** fewer human-readable captures and uneven CBOR library quality.
- **Security analysis:** canonical form removes representation malleability but
  cannot fix semantic aliasing in a bad application resource schema.
- **Performance impact:** small records and bounded single-pass decoding; schema
  validation adds predictable CPU.
- **Compatibility impact:** standard CBOR/COSE libraries exist; JSON gateways
  preserve native signed bytes.
- **Future extensibility:** registered integer keys/tags and critical extensions;
  another native encoding needs a separate profile and vectors.

### C.2 Compression restrictions

- **Problem:** model and tool data can be large.
- **Threat:** length oracles, dictionary confusion, and decompression bombs can
  leak secrets or exhaust resources.
- **Design:** `none` by default; RFC 8878 zstd only for bounded non-secret,
  single-origin bodies with signed public dictionaries.
- **Alternatives:** always compress, TLS compression, gzip, or padding alone.
- **Tradeoffs:** less bandwidth saving for sensitive traffic in exchange for no
  shared secret/attacker compression context.
- **Advantages:** predictable resource bounds and a small required implementation.
- **Disadvantages:** larger encrypted messages where secrecy prevents compression.
- **Security analysis:** the rule removes known oracle preconditions; length may
  still leak and padding needs a separate profile.
- **Performance impact:** `none` costs no CPU; zstd is budgeted by output and ratio.
- **Compatibility impact:** zstd is standardized; unknown algorithms fail rather
  than silently falling back.
- **Future extensibility:** new codecs require bomb, oracle, dictionary, and
  vector analysis.

### C.3 Transcript-bound negotiation

- **Problem:** long-lived standards need version and cryptographic agility.
- **Threat:** an attacker strips strong offers or confuses application and
  transport versions.
- **Design:** exact offers, security floors, complete registered suites, ALPN,
  signed transcript, mutual FINISH, and no same-endpoint legacy retry.
- **Alternatives:** highest-number-only, implicit HTTP negotiation, or fallback.
- **Tradeoffs:** a larger handshake and explicit failure provide reliable
  agreement and controlled deprecation.
- **Advantages:** downgrade evidence and deterministic selection.
- **Disadvantages:** obsolete endpoints need planned parallel-version migration.
- **Security analysis:** network stripping is detected; deliberate operator
  lowering of local minimum policy is outside that protection.
- **Performance impact:** one transcript hash and FINISH per peer.
- **Compatibility impact:** resembles TLS/SSH negotiation while binding the full
  SMCP application suite.
- **Future extensibility:** additive minors and critical extensions; incompatible
  semantics use a new major and ALPN.

### C.4 Out-of-process plugin model

- **Problem:** deployments need interchangeable identity, policy, risk, audit,
  transport, and registry providers.
- **Threat:** arbitrary in-process plugins inherit secrets and can bypass the PEP.
- **Design:** plugins are separately identified, manifested, sandboxed SMCP
  services with narrow capabilities and signed results.
- **Alternatives:** shared-library hooks, arbitrary scripts, or one privileged
  monolith.
- **Tradeoffs:** IPC latency and more deployment units buy isolation, attribution,
  and independent updates.
- **Advantages:** a smaller TCB and uniform local/remote provider semantics.
- **Disadvantages:** provider discovery, lifecycle, and availability management.
- **Security analysis:** isolation limits ordinary compromise; kernel compromise
  remains, and a trusted provider can misstate facts within its role.
- **Performance impact:** cache/batch only to signed freshness bounds; local IPC
  serves hot providers.
- **Compatibility impact:** existing HSM, PDP, SPIFFE, registry, and SIEM systems
  fit typed adapters.
- **Future extensibility:** add a signed SPI and actions, never generic execution
  inside the TCB.

### C.5 Structured safe errors

- **Problem:** peers need interoperable recovery without implementation leakage.
- **Threat:** stack, identity, or resource disclosure; retry storms; duplicate
  side effects.
- **Design:** facility/reason, explicit retry class, related state, safe
  requirement, and random support correlation; every error is signed.
- **Alternatives:** free-text exceptions, HTTP status alone, or JSON-RPC errors.
- **Tradeoffs:** registry governance and less detail on the remote interface.
- **Advantages:** machine-safe retries and cross-transport semantics.
- **Disadvantages:** operators need a separate protected diagnostic channel.
- **Security analysis:** uniform errors limit enumeration; timing and traffic may
  still leak without profile padding.
- **Performance impact:** negligible, with rate limits preventing amplification.
- **Compatibility impact:** gateways map source errors conservatively and never
  infer mutation retry safety.
- **Future extensibility:** allocate within a facility; unknown mutation errors
  default to no automatic retry.

### C.6 Compliance profiles

- **Problem:** web, workload, local, relay, constrained, and regulated systems
  need different mechanisms without ambiguous “secure” claims.
- **Threat:** optional controls and marketing labels create weakest-link profiles.
- **Design:** indivisible Core plus precisely tested additive profiles with build,
  provider, suite, and expiry metadata.
- **Alternatives:** one oversized stack or arbitrary feature flags.
- **Tradeoffs:** a larger test matrix yields clear, composable assurance.
- **Advantages:** peers and buyers can compare exact properties.
- **Disadvantages:** profile and certification governance grows over time.
- **Security analysis:** a claim proves tested mechanics, not safe local policy,
  endpoint integrity, or legal compliance.
- **Performance impact:** constrained fixes choices; high assurance adds fresh
  status, attestation, and witness cost.
- **Compatibility impact:** profiles align Web/OAuth, SPIFFE, local, supply-chain,
  relay, and regulated ecosystems.
- **Future extensibility:** new profiles strengthen Core and publish assertions.

### C.7 Explicit state machines

- **Problem:** asynchronous retries, cancellation, crashes, and revocation make
  action outcome ambiguous.
- **Threat:** early messages, replay, double execution, TOCTOU, and unsafe retry.
- **Design:** closed session states plus journaled two-phase operations, atomic
  security epoch, idempotency key, and authoritative reconciliation.
- **Alternatives:** stateless RPC, distributed two-phase commit across every tool,
  or client retry conventions.
- **Tradeoffs:** reservation/journal state and one effect round trip.
- **Advantages:** exact consent, unique effect, and deterministic crash recovery.
- **Disadvantages:** non-atomic legacy dependencies may be rejected at high
  assurance.
- **Security analysis:** the boundary is protected only if an adapter's atomicity
  claims are true and audited.
- **Performance impact:** reads stay one phase; effects pay prepare/commit and
  durable journal writes.
- **Compatibility impact:** maps to database transactions and idempotency APIs;
  legacy calls terminate at a gateway.
- **Future extensibility:** action profiles may add stronger workflows without
  weakening unique commit.

### C.8 Shared reference SDK core

- **Problem:** language SDKs diverge on canonicalization, validation order,
  authorization, and state.
- **Threat:** one permissive binding becomes an ecosystem bypass.
- **Design:** a memory-safe reference core, safe high-level APIs, common vectors,
  and behavioral conformance.
- **Alternatives:** prose-only implementations or generated RPC stubs.
- **Tradeoffs:** FFI/WASM packaging complexity versus one reviewed semantics core;
  independent implementations still detect common-mode bugs.
- **Advantages:** fewer unsafe knobs and faster cross-language fixes.
- **Disadvantages:** a core vulnerability can affect several bindings.
- **Security analysis:** shared code is not proof; differential implementations
  and provider isolation remain required.
- **Performance impact:** native/WASM execution is small; FFI copies are bounded.
- **Compatibility impact:** idiomatic APIs hide wire mechanics while receipts stay
  portable.
- **Future extensibility:** typed bindings carry schema/registry digest and retain
  unknown informational metadata without interpreting it.

### C.9 MCP migration gateway

- **Problem:** adoption must coexist with deployed MCP clients and tools.
- **Threat:** transparent translation launders unsigned legacy data into claimed
  SMCP identity, authority, provenance, or audit.
- **Design:** a named termination principal, token exchange, unverified synthesized
  manifest fields, source/mapping digests, conservative effects, and separate
  fallback address.
- **Alternatives:** flag-day replacement, transparent mapping, or auto-downgrade.
- **Tradeoffs:** reduced assurance and gateway trust during staged adoption.
- **Advantages:** immediate policy, consent, sandbox, audit, and a measurable path
  to native endpoints.
- **Disadvantages:** no gateway can create origin signatures, runtime attestation,
  or publisher provenance that the legacy side lacks.
- **Security analysis:** compromise affects the gateway's explicit scope; narrow
  capabilities, isolation, monitoring, and sunset limit it.
- **Performance impact:** translation and prepare/commit add legacy call latency.
- **Compatibility impact:** business schemas are preserved only when the
  security-critical mapping is lossless or explicitly downgraded.
- **Future extensibility:** the same assurance taxonomy can profile HTTP, gRPC,
  Kubernetes, and queue gateways.
