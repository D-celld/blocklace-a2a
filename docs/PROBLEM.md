# The A2A Audit Gap

## Background

The Agent2Agent (A2A) protocol enables AI agents from different organizations to communicate and collaborate. Originally launched by Google and now under the Linux Foundation, A2A has 150+ partners including Salesforce, SAP, ServiceNow, Microsoft, and AWS.

## What A2A Provides

A2A includes robust security primitives:

- **Transport Security**: TLS 1.2+ for encrypted communication
- **Authentication**: OAuth 2.0, JWT, or API keys
- **Agent Identity**: Signed Agent Cards (JSON-LD documents)
- **Authorization**: Capability-based access control

These mechanisms establish trust at the connection level.

## What A2A Lacks

A2A does not provide:

### 1. Message-Level Cryptographic Audit Trail

Messages are authenticated at the transport level, but there is no mechanism to prove the sequence and content of messages after the fact. If disputes arise, there is no cryptographic evidence of what was said.

### 2. Tamper-Proof History

Once a message is delivered, there is no hash chain linking it to previous messages. A malicious party could modify records of past interactions without detection.

### 3. Equivocation Detection

An agent can send conflicting messages to different parties. For example:
- Agent C tells Agent A: "Approved for $100"
- Agent C tells Agent B: "Approved for $999"

Without a shared ledger, neither A nor B can detect that C is being inconsistent.

## Real-World Impact

### Financial Transactions

Multi-agent systems processing financial requests need provable audit trails. Without them, disputes require manual reconciliation.

### Regulatory Compliance

Industries like healthcare and finance may require tamper-evident logs of AI agent decisions. A2A alone cannot provide this.

### Multi-Party Coordination

Complex workflows involving multiple organizations need assurance that all parties are seeing consistent state.

## Solution Requirements

A complete solution must:

1. **Maintain full A2A compatibility** - No changes to transport or authentication
2. **Add per-message proofs** - Each message cryptographically signed
3. **Create hash chains** - Link messages in causal order
4. **Enable equivocation detection** - Detect conflicting statements
5. **Minimize overhead** - Light enough for high-volume communication

Blocklace provides these guarantees as a middleware layer on top of A2A.
