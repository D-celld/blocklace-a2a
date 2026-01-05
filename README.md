<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="Blocklace A2A" width="120">
  </picture>

  <h1>Blocklace A2A</h1>

  <p>Cryptographic audit layer for the <a href="https://a2a-protocol.org/">A2A protocol</a>.</p>
</div>

---

## Problem

A2A secures the transport layer (TLS, OAuth). It does not secure the message layer:

- **No audit trail** — messages aren't hash-chained
- **No tamper detection** — records can be modified after delivery
- **No equivocation detection** — an agent can send conflicting messages to different parties

## Solution

Blocklace adds message-level cryptographic guarantees on top of A2A:

| Capability | A2A | + Blocklace |
|------------|:---:|:-----------:|
| Transport encryption | Yes | — |
| Authentication | Yes | — |
| Per-message signatures | — | Yes |
| Hash-chained history | — | Yes |
| Tamper detection | — | Yes |
| Equivocation detection | — | Yes |
| Causal ordering | — | Yes |

Blocklace complements A2A. It does not replace TLS/OAuth.

## How It Works

Each message becomes a signed block in a DAG:

```
Block {
  author: "org-a"
  content: "Approved: $100"
  parents: ["67a3e7bf"]      ← hash pointers to prior blocks
  hash: sha256(above)
  signature: ed25519(hash)
}
```

Equivocation is detected when the same author creates two blocks where neither is an ancestor of the other.

## Demo

```
$ python demo.py

Registering agents...
  [OK] org-a (pk: 4a4ccb1f...)
  [OK] org-b (pk: 3aff0ee5...)
  [OK] org-c (pk: 736199f4...)

Appending blocks...
  [84c7b686] author=org-a parents=[]         content="Hello from A"
  [44ed8588] author=org-b parents=[84c7b686] content="Hello from B"
  [67a3e7bf] author=org-a parents=[44ed8588] content="Reply from A"

Simulating equivocation (org-c sends conflicting messages)...
  [63eb9c6b] author=org-c parents=[67a3e7bf] content="Approved: $100"
  [35331451] author=org-c parents=[67a3e7bf] content="Approved: $999"

Equivocation detected:
  author:    org-c
  block_1:   63eb9c6b (content="Approved: $100")
  block_2:   35331451 (content="Approved: $999")
  evidence:  Blocks share parent [67a3e7bf] with no causal relationship
```

## Installation

```bash
pip install git+https://github.com/en-yao/blocklace-a2a.git
```

Requires Python 3.10+.

## Quick Start

```python
from blocklace_a2a import Blocklace, AgentId

lace = Blocklace()
keys = lace.register_agent(AgentId("org-a"))
result = lace.append(keys, "Hello from A")
print(result.block.short_hash)  # "84c7b686"
```

## Integration

Wrap A2A message passing with middleware:

```python
from blocklace_a2a import Blocklace, create_middleware

lace = Blocklace()
middleware = create_middleware(lace, "my-agent")

# Outgoing
envelope = middleware.wrap_outgoing({"task": "process", "data": "..."})
payload = envelope.to_dict()  # JSON-serializable

# Incoming
result = middleware.verify_incoming(received_envelope)
if not result.valid:
    raise SecurityError(result.errors)
```

See [`examples/a2a_integration.py`](examples/a2a_integration.py) for a complete example.

## Limitations

| Limitation | Explanation |
|------------|-------------|
| **Proves provenance, not correctness** | Proves who said what, not whether it's true |
| **Detection, not prevention** | Detects Byzantine behavior after the fact |
| **Append-only** | No rollback; history is immutable |
| **Requires key isolation** | Shared private keys defeat the purpose |
| **In-memory only** | This implementation is for demonstration |

## Status

Proof of concept. Suitable for experimentation and learning. Not production-ready.

## References

- [A2A Protocol](https://a2a-protocol.org/)
- [The Blocklace: A Byzantine-repelling and Universal CRDT](https://arxiv.org/abs/2402.08068) (Almeida & Shapiro, 2024)

## License

MIT
