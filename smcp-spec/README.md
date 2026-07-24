# Secure Model Communication Protocol (SMCP)

This directory contains a pre-standard engineering specification for SMCP, a
secure-by-construction protocol for communication among humans, agents, tools,
services, and infrastructure.

SMCP is not an MCP extension and this directory is not an implementation. It is
an independent standards work item. Version `0.1.0-draft.1` is suitable for
design review, threat-model review, prototyping, and interoperability work; it
does not claim IETF consensus or production deployment status.

## Documents

- [`draft-smcp-core.md`](draft-smcp-core.md) is the normative protocol
  specification. Its sections 1 through 37 correspond exactly to the requested
  deliverables.
- [`smcp-v1.cddl`](smcp-v1.cddl) is the normative deterministic-CBOR and COSE
  schema for every core message, credential, receipt, manifest, and audit event.
- [`registries.md`](registries.md) defines initial protocol registries and the
  registration policy.
- [`security-and-conformance.md`](security-and-conformance.md) gives executable
  conformance requirements, negative vectors, fuzz targets, and formal-model
  properties.

## Normative language and design status

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are to be interpreted as described by BCP 14 when, and only when,
they appear in all capitals.

Security invariants override extension behavior and deployment preferences.
Where this draft selects algorithms, it uses existing IETF, W3C, FIDO, SPIFFE,
TUF, Sigstore, and in-toto mechanisms; it defines no cryptographic primitive.

## Reading order

Read the core document first. Implementers should then treat the CDDL and
registries as normative, and use the security/conformance document as the
minimum release gate. A conflict is resolved in this order:

1. security invariants in the core specification;
2. normative prose in the core specification;
3. the CDDL schema;
4. the registry tables;
5. examples and explanatory text.
