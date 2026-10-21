# SMCP Python SDK


<div align="center">

<strong>Python implementation of the Secure Model Context Protocol (SMCP)</strong>

[![PyPI][pypi-badge]][pypi-url]
[![MIT licensed][mit-badge]][mit-url]
[![Python Version][python-badge]][python-url]
[![Documentation][docs-badge]][docs-url]
[![Protocol][protocol-badge]][protocol-url]
[![Specification][spec-badge]][spec-url]

</div>

> [!NOTE]
> **SMCP (Secure Model Context Protocol)** is a security-first protocol for AI systems, agents, tools, services, and applications. While inspired by the ecosystem surrounding the Model Context Protocol (MCP), **SMCP is an independent protocol with its own specification, architecture, security model, and implementation.**
>
> SMCP is **not an extension, fork, profile, or compatible mode of MCP**. It defines its own protocol semantics, transport abstractions, authentication model, capability negotiation, and security guarantees.

---

# Documentation

**The documentation lives at <https://docs.smcp.dev>.**

It includes:

- Getting Started
- Installation Guide
- Server Development
- Client Development
- Authentication
- Authorization
- Cryptography
- Capability Negotiation
- Session Management
- Secure Transport
- API Reference
- Specification
- Security Best Practices
- Examples

---

# What is SMCP?

The **Secure Model Context Protocol (SMCP)** is an open protocol for securely connecting AI models, autonomous agents, tools, services, APIs, and enterprise infrastructure.

SMCP is designed around one primary goal:

> **Security by Design.**

Instead of treating authentication, authorization, encryption, auditing, and policy enforcement as optional extensions, SMCP makes them **core protocol primitives**.

With this SDK you can:

- Build secure SMCP servers
- Build secure SMCP clients
- Expose tools, resources, prompts, workflows, agents, and services
- Connect AI agents with enterprise systems
- Use secure capability negotiation
- Authenticate every participant
- Authorize every operation
- Encrypt communication end-to-end
- Build distributed AI systems safely

---

# Why SMCP?

Modern AI systems need significantly stronger security than traditional API protocols.

SMCP was designed to address problems such as:

- Unauthorized tool execution
- Prompt injection
- Context poisoning
- Capability escalation
- Credential leakage
- Replay attacks
- Session hijacking
- Supply-chain attacks
- Agent impersonation
- Unauthorized delegation

Rather than relying on application-level defenses, SMCP incorporates security directly into the protocol itself.

---

# Features

## Security First

Security is built into every layer of the protocol.

- Strong authentication
- Fine-grained authorization
- Secure sessions
- Identity verification
- Cryptographic signatures
- Encrypted communication
- Policy enforcement
- Audit events

---

## Capability-Based Access

Everything is protected using explicit capabilities.

Servers never expose functionality implicitly.

Clients only receive the permissions they have been granted.

---

## Secure Sessions

SMCP provides secure session lifecycle management including:

- Session establishment
- Session renewal
- Session expiration
- Session revocation
- Secure reconnect

---

## Multiple Transports

SMCP supports multiple transport layers including:

- STDIO
- HTTP
- HTTPS
- Streamable HTTP
- WebSocket
- Unix Domain Socket
- Named Pipes
- Custom transports

---

## Enterprise Ready

Designed for production deployments.

Features include:

- Multi-tenancy
- Policy engines
- Identity providers
- Audit logging
- Secret management
- Service-to-service authentication
- High availability

---

## Extensible

SMCP was designed for long-term evolution.

New capabilities, transports, authentication methods, message types, and extensions can be added without breaking existing implementations.

---

# Requirements

Python 3.11+

---

# Installation

```bash
pip install smcp
```

or

```bash
uv add smcp
```

---

# A Secure Server in 15 Lines

```python
from smcp.server import SMCPServer

server = SMCPServer(
    name="Calculator",
)

@server.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b

@server.resource("greeting://{name}")
def greeting(name: str) -> str:
    return f"Hello, {name}!"
```

Run the server:

```bash
python server.py
```

The SDK automatically handles:

- Schema generation
- Validation
- Session management
- Authentication
- Authorization
- Secure messaging
- Protocol negotiation

---

# A Secure Client

```python
import asyncio

from smcp import Client

async def main():

    async with Client("https://localhost:8443") as client:

        result = await client.call_tool(
            "add",
            {
                "a": 1,
                "b": 2
            }
        )

        print(result)

asyncio.run(main())
```

The client automatically manages:

- Authentication
- Secure sessions
- Capability negotiation
- Connection management
- Encryption
- Retry policies

---

# Core Concepts

SMCP revolves around several core abstractions.

## Servers

Servers expose secure capabilities to authenticated clients.

Examples:

- Tools
- Resources
- Prompts
- Agents
- Workflows
- Services

---

## Clients

Clients securely discover and invoke remote capabilities.

---

## Capabilities

Capabilities define exactly what an authenticated identity is allowed to access.

Capabilities replace unrestricted access with explicit permissions.

---

## Sessions

Sessions provide authenticated communication between participants.

Sessions include:

- Identity
- Authorization
- Cryptographic state
- Expiration
- Security metadata

---

## Policies

Policies define authorization rules.

Examples include:

- User permissions
- Agent permissions
- Resource permissions
- Organization policies
- Runtime restrictions

---

# Security

Security is the primary design goal of SMCP.

The protocol includes built-in support for:

- Authentication
- Authorization
- Secure session establishment
- Identity verification
- Capability negotiation
- Message integrity
- Replay protection
- Cryptographic signatures
- Secure delegation
- Audit logging
- Policy enforcement

---

# Architecture

```
+----------------------+
|      AI Client       |
+----------+-----------+
           |
           |
      Secure Session
           |
+----------v-----------+
|      SMCP Server     |
+----------+-----------+
           |
  +--------+---------+
  |                  |
  |                  |
Tools          Resources
  |                  |
Workflows      Enterprise APIs
```

---

# Example Use Cases

SMCP can be used for:

- AI Agents
- Coding Assistants
- Enterprise AI
- Autonomous Systems
- Workflow Automation
- Tool Execution
- Secure API Gateways
- Multi-Agent Systems
- Robotics
- Cloud Platforms
- Research Infrastructure

---

# Roadmap

- [x] Core Protocol
- [x] Python SDK
- [ ] Rust SDK
- [ ] Go SDK
- [ ] Java SDK
- [ ] TypeScript SDK
- [ ] Inspector
- [ ] CLI
- [ ] Developer Portal
- [ ] Conformance Test Suite
- [ ] Reference Server
- [ ] Reference Client

---

# Contributing

Contributions are welcome.

Whether you're fixing bugs, improving documentation, designing protocol extensions, or implementing SDKs in new languages, we'd love your help.

See **CONTRIBUTING.md** for details.

---

# License

This project is licensed under the MIT License.

See **LICENSE** for more information.

---

[pypi-badge]: https://img.shields.io/pypi/v/smcp.svg
[pypi-url]: https://pypi.org/project/smcp/

[mit-badge]: https://img.shields.io/pypi/l/smcp.svg
[mit-url]: LICENSE

[python-badge]: https://img.shields.io/pypi/pyversions/smcp.svg
[python-url]: https://www.python.org

[docs-badge]: https://img.shields.io/badge/docs-smcp-blue.svg
[docs-url]: https://docs.smcp.dev

[protocol-badge]: https://img.shields.io/badge/protocol-smcp-blue.svg
[protocol-url]: https://smcp.dev

[spec-badge]: https://img.shields.io/badge/spec-smcp-blue.svg
[spec-url]: https://spec.smcp.dev
