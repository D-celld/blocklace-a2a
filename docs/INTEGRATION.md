# Integration Guide

This guide explains how to add Blocklace to an existing A2A setup.

## Prerequisites

- Python 3.10+
- Existing A2A agent implementation
- `pip install git+https://github.com/en-yao/blocklace-a2a.git`

## Architecture

Blocklace operates as middleware between your application and A2A transport:

```
Your App ──> Blocklace Middleware ──> A2A Transport ──> Network
                    │
                    └── Local Blocklace (DAG storage)
```

## Basic Setup

### 1. Create Shared Blocklace

```python
from blocklace_a2a import Blocklace

# Shared across your organization's agents
lace = Blocklace()
```

### 2. Create Middleware for Each Agent

```python
from blocklace_a2a import create_middleware

middleware = create_middleware(
    lace,
    agent_id="my-org/my-agent",
    on_equivocation=handle_equivocation  # optional callback
)
```

### 3. Wrap Outgoing Messages

```python
def send_message(recipient: str, content: dict):
    # Create Blocklace envelope
    envelope = middleware.wrap_outgoing(content)

    # Serialize for transport
    payload = envelope.to_dict()

    # Send via your existing A2A transport
    a2a_client.send(recipient, payload)
```

### 4. Verify Incoming Messages

```python
from blocklace_a2a import MessageEnvelope

def receive_message(payload: dict):
    # Reconstruct envelope
    envelope = MessageEnvelope.from_dict(payload)

    # Verify with Blocklace
    result = middleware.verify_incoming(envelope)

    if not result.valid:
        raise SecurityError(f"Invalid message: {result.errors}")

    if result.warnings:
        log_warnings(result.warnings)

    # Process verified content
    return envelope.content
```

## Multi-Organization Setup

For cross-organization communication, each org maintains their own Blocklace view.

### Registering Remote Agents

```python
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def register_remote_agent(agent_id: str, public_key_pem: bytes):
    public_key = load_pem_public_key(public_key_pem)
    lace.register_agent_with_key(AgentId(agent_id), public_key)
```

### Key Exchange

Public keys can be exchanged via:
- A2A Agent Cards (recommended)
- Out-of-band key ceremony
- PKI/CA infrastructure

## Handling Equivocation

```python
def handle_equivocation(error: EquivocationError):
    """Called when equivocation is detected."""
    log.critical(
        f"EQUIVOCATION: Agent {error.author} produced "
        f"conflicting blocks {error.block1.short_hash} "
        f"and {error.block2.short_hash}"
    )

    # Your response:
    # - Alert operations team
    # - Quarantine the agent
    # - Trigger dispute resolution
    # - Log for compliance
```

## Audit Trail Retrieval

```python
def get_complete_history(message_hash: str):
    """Get full causal history for a message."""
    trail = middleware.get_audit_trail(message_hash)

    for block in trail:
        print(f"{block.short_hash} | {block.author} | {block.content}")
```

## Chain Verification

```python
from blocklace_a2a import verify_chain

def periodic_verification():
    """Run this periodically or before critical operations."""
    result = verify_chain(lace)

    if not result.valid:
        raise IntegrityError(f"Chain verification failed: {result.errors}")

    for warning in result.warnings:
        log.warning(warning)
```

## Best Practices

### 1. Store Blocklace State

This implementation is in-memory. For production:
- Persist blocks to database
- Implement block sync between nodes
- Consider append-only log storage

### 2. Parent Selection

When sending messages in a conversation:

```python
# Reference the message you're replying to
envelope = middleware.wrap_outgoing(
    response_content,
    parents=(request_hash,)
)
```

### 3. Performance Considerations

- Verification is O(ancestors) for full chain
- Use `verify_block()` for quick single-block checks
- Batch verify during low-traffic periods

### 4. Error Handling

```python
from blocklace_a2a import (
    BlocklaceError,
    EquivocationError,
    TamperError,
    UnknownAgentError,
)

try:
    result = middleware.verify_incoming(envelope)
except UnknownAgentError as e:
    # Sender not registered - request their public key
    request_agent_registration(e.agent_id)
except TamperError as e:
    # Message integrity compromised
    report_security_incident(e)
```

## Example: Full Integration

See `examples/a2a_integration.py` for a complete working example including:
- Multi-agent setup
- Message exchange
- Tamper detection
- Equivocation handling
- Audit trail retrieval
