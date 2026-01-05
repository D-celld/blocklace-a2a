#!/usr/bin/env python3
"""Complete A2A Integration Example.

This example shows how to integrate Blocklace with A2A agent communication.
It demonstrates:

1. Creating a shared Blocklace for multi-org agents
2. Wrapping A2A messages with cryptographic proofs
3. Verifying incoming messages
4. Detecting and handling equivocation attempts

In production, each organization would:
- Run their own agent with their private key
- Share a common Blocklace view (via P2P gossip or shared ledger)
- Verify all incoming messages before processing

This example simulates two organizations communicating.
"""

import json
from dataclasses import dataclass
from typing import Any

from blocklace_a2a import (
    A2AMiddleware,
    AgentId,
    Blocklace,
    EquivocationError,
    MessageEnvelope,
    create_middleware,
)


@dataclass
class A2AMessage:
    """Simulated A2A protocol message."""

    sender: str
    recipient: str
    task_type: str
    payload: dict[str, Any]


def simulate_a2a_transport(envelope: MessageEnvelope) -> str:
    """Simulate A2A HTTP transport by serializing to JSON."""
    return json.dumps(envelope.to_dict())


def receive_a2a_transport(json_data: str) -> MessageEnvelope:
    """Simulate receiving A2A message from transport."""
    data = json.loads(json_data)
    return MessageEnvelope.from_dict(data)


def main() -> None:
    print("A2A Integration Example")
    print("=" * 50)
    print()

    # In production: Each org maintains their own Blocklace view
    # Here we simulate a shared view for simplicity
    shared_lace = Blocklace()

    # Organization A sets up their agent
    print("[Org A] Setting up agent...")
    mw_a = create_middleware(shared_lace, "org-a-agent")
    print(f"  Agent ID: {mw_a.agent_keys.agent_id}")
    print(f"  Public Key: {mw_a.agent_keys.public_key_hex}")
    print()

    # Organization B sets up their agent with equivocation callback
    equivocation_alerts: list[EquivocationError] = []

    def on_equivocation(err: EquivocationError) -> None:
        equivocation_alerts.append(err)
        print(f"  [ALERT] Equivocation detected from {err.author}!")

    print("[Org B] Setting up agent...")
    mw_b = create_middleware(
        shared_lace, "org-b-agent", on_equivocation=on_equivocation
    )
    print(f"  Agent ID: {mw_b.agent_keys.agent_id}")
    print(f"  Public Key: {mw_b.agent_keys.public_key_hex}")
    print()

    # Scenario 1: Normal message exchange
    print("-" * 50)
    print("Scenario 1: Normal A2A Message Exchange")
    print("-" * 50)
    print()

    # Org A sends a task request
    task_request = A2AMessage(
        sender="org-a-agent",
        recipient="org-b-agent",
        task_type="data_processing",
        payload={"dataset": "sales_q4", "operation": "aggregate"},
    )

    print("[Org A] Sending task request...")
    envelope_a1 = mw_a.wrap_outgoing(task_request.__dict__)
    transport_data = simulate_a2a_transport(envelope_a1)
    print(f"  Block: {envelope_a1.block_hash[:8]}")
    print(f"  Transport size: {len(transport_data)} bytes")
    print()

    # Org B receives and verifies
    print("[Org B] Receiving and verifying message...")
    received = receive_a2a_transport(transport_data)
    result = mw_b.verify_incoming(received)

    if result.valid:
        print("  Verification: PASSED")
        print(f"  From: {received.author}")
        print(f"  Content: {received.content['task_type']}")
    else:
        print(f"  Verification: FAILED - {result.errors}")
    print()

    # Org B sends response
    task_response = A2AMessage(
        sender="org-b-agent",
        recipient="org-a-agent",
        task_type="task_result",
        payload={"status": "completed", "rows_processed": 10000},
    )

    print("[Org B] Sending response...")
    envelope_b1 = mw_b.wrap_outgoing(
        task_response.__dict__, parents=(envelope_a1.block_hash,)
    )
    print(f"  Block: {envelope_b1.block_hash[:8]}")
    print(f"  References: {envelope_a1.block_hash[:8]} (Org A's request)")
    print()

    # Scenario 2: Detecting tampering
    print("-" * 50)
    print("Scenario 2: Detecting Message Tampering")
    print("-" * 50)
    print()

    # Attacker tries to modify a message
    print("[Attacker] Attempting to modify message content...")
    tampered_data = json.loads(transport_data)
    tampered_data["content"]["payload"]["operation"] = "delete_all"  # Malicious!
    tampered = MessageEnvelope.from_dict(tampered_data)

    result = mw_b.verify_incoming(tampered)
    if not result.valid:
        print("  Detection: SUCCESS - Tampering detected!")
        print(f"  Errors: {result.errors}")
    print()

    # Scenario 3: Equivocation detection
    print("-" * 50)
    print("Scenario 3: Equivocation Detection")
    print("-" * 50)
    print()

    # Malicious Org C sends conflicting approvals
    print("[Org C] Setting up malicious agent...")
    mw_c = create_middleware(shared_lace, "org-c-agent")
    print()

    # Create a base message that both approvals reference
    base = mw_c.wrap_outgoing({"type": "quote_request", "amount": 1000})
    print(f"[Org C] Sent quote request: {base.block_hash[:8]}")

    # Send first approval
    approval_1 = mw_c.wrap_outgoing(
        {"type": "approval", "amount": 100, "recipient": "org-a"},
        parents=(base.block_hash,),
    )
    print(f"[Org C] Sent approval to Org A: $100 ({approval_1.block_hash[:8]})")

    # Try to send conflicting approval to Org B
    approval_2 = mw_c.wrap_outgoing(
        {"type": "approval", "amount": 999, "recipient": "org-b"},
        parents=(base.block_hash,),  # Same parent = equivocation!
    )
    print(f"[Org C] Sent approval to Org B: $999 ({approval_2.block_hash[:8]})")
    print()

    # Org B receives both and detects equivocation
    print("[Org B] Receiving Org C's messages...")
    mw_b.verify_incoming(base)
    mw_b.verify_incoming(approval_1)
    result = mw_b.verify_incoming(approval_2)

    if result.warnings:
        print("  Warnings detected:")
        for w in result.warnings:
            print(f"    - {w}")

    print()

    # Show audit trail
    print("-" * 50)
    print("Audit Trail")
    print("-" * 50)
    print()

    print("Complete message chain for Org B's response:")
    trail = mw_b.get_audit_trail(envelope_b1.block_hash)
    for block in trail:
        content_preview = str(block.content)[:40]
        print(f"  {block.short_hash} | {block.author:15} | {content_preview}...")
    print()

    # Summary
    print("-" * 50)
    print("Summary")
    print("-" * 50)
    print(f"  Total blocks: {shared_lace.block_count}")
    print(f"  Total agents: {shared_lace.agent_count}")
    print(f"  Equivocation alerts: {len(equivocation_alerts)}")
    print()
    print("Done.")


if __name__ == "__main__":
    main()
