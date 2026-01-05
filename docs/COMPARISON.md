# Technical Comparison: A2A vs Blocklace

## Overview

| Feature | A2A | Blocklace |
|---------|-----|-----------|
| Transport Security | TLS | - |
| Authentication | OAuth/JWT | - |
| Per-Message Signatures | - | Ed25519 |
| Replay Protection | - | Hash chain |
| Message Ordering | - | Causal (DAG) |
| Tamper Detection | - | Hash chain |
| Equivocation Detection | - | DAG analysis |
| Historical Verification | - | Yes |

## Detailed Analysis

### A2A Base Protocol

A2A provides connection-level security:

```
Client ──TLS/mTLS──> Server
         │
         └── OAuth 2.0 token or API key
```

**Strengths:**
- Industry-standard transport security
- Flexible authentication options
- Wide vendor support

**Limitations:**
- No message-level proofs
- Cannot verify historical message sequence
- No detection of conflicting statements

### Blocklace

Blocklace adds a DAG structure with hash pointers:

```
Block {
  author: "org-a"
  content: {...}
  parents: ["hash1", "hash2"]  // Causal links
  hash: sha256(canonical_json(above))
  signature: ed25519_sign(hash)
}
```

**Strengths:**
- Complete audit trail via hash chain
- Equivocation detection via DAG structure
- Causal ordering of all messages
- Historical verification

**Limitations:**
- Additional storage per message
- Requires DAG traversal for some operations

## Equivocation Detection

The key differentiator of Blocklace is equivocation detection.

### The Problem

```
             ┌── "Approved $100" ──> Agent A
Agent C ────┤
             └── "Approved $999" ──> Agent B
```

With A2A alone, A and B cannot detect this inconsistency.

### Blocklace Solution

```
         ┌── Block X: "Approved $100" (parent: P)
Agent C ─┤
         └── Block Y: "Approved $999" (parent: P)
```

When Block X and Y have the same parent but neither references the other, equivocation is detected:

```python
For blocks B1, B2 by same author:
  if not is_ancestor(B1, B2) and not is_ancestor(B2, B1):
    return EQUIVOCATION
```

## Overhead Comparison

| Metric | A2A | Blocklace |
|--------|-----|-----------|
| Added bytes/message | 0 | ~200 |
| CPU per message | - | 1 sign + 1 verify + hash |
| Storage | 0 | O(n) blocks |
| Verification complexity | O(1) | O(ancestors) |

The overhead is acceptable for most use cases. High-frequency trading or real-time gaming may need optimization.

## When to Use Each

### Use A2A alone when:
- Trust between agents is high
- No audit trail required
- Disputes unlikely or handled out-of-band

### Use Blocklace when:
- Tamper-proof audit trail required
- Multi-party coordination with potential disputes
- Regulatory compliance requirements
- Need to detect conflicting statements
