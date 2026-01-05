#!/usr/bin/env python3
"""Blocklace A2A Demo.

This demo shows the core functionality of Blocklace for A2A:
1. Agent registration with Ed25519 key pairs
2. Block creation with hash chaining
3. Multi-agent message passing
4. Equivocation detection

Run with: python demo.py
"""

from blocklace_a2a import AgentId, Blocklace


def main() -> None:
    print("blocklace-a2a demo")
    print("==================")
    print()

    # Create a new Blocklace
    lace = Blocklace()

    # Register agents
    print("Registering agents...")
    keys_a = lace.register_agent(AgentId("org-a"))
    print(f"  [OK] org-a (pk: {keys_a.public_key_hex})")

    keys_b = lace.register_agent(AgentId("org-b"))
    print(f"  [OK] org-b (pk: {keys_b.public_key_hex})")

    keys_c = lace.register_agent(AgentId("org-c"))
    print(f"  [OK] org-c (pk: {keys_c.public_key_hex})")
    print()

    # Append blocks
    print("Appending blocks...")

    result_a1 = lace.append(keys_a, "Hello from A")
    print(
        f"  [{result_a1.block.short_hash}] author=org-a "
        f"parents={format_parents(result_a1.block.parents):16} "
        f'content="{result_a1.block.content}"'
    )

    result_b1 = lace.append(
        keys_b, "Hello from B", parents=(result_a1.block.block_hash,)
    )
    print(
        f"  [{result_b1.block.short_hash}] author=org-b "
        f"parents={format_parents(result_b1.block.parents):16} "
        f'content="{result_b1.block.content}"'
    )

    result_a2 = lace.append(
        keys_a, "Reply from A", parents=(result_b1.block.block_hash,)
    )
    print(
        f"  [{result_a2.block.short_hash}] author=org-a "
        f"parents={format_parents(result_a2.block.parents):16} "
        f'content="{result_a2.block.content}"'
    )
    print()

    # Simulate equivocation
    print("Simulating equivocation (org-c sends conflicting messages)...")

    result_c1 = lace.append(
        keys_c, "Approved: $100", parents=(result_a2.block.block_hash,)
    )
    print(
        f"  [{result_c1.block.short_hash}] author=org-c "
        f"parents={format_parents(result_c1.block.parents):16} "
        f'content="{result_c1.block.content}"'
    )

    # This creates an equivocation - same parent but different content
    result_c2 = lace.append(
        keys_c, "Approved: $999", parents=(result_a2.block.block_hash,)
    )
    print(
        f"  [{result_c2.block.short_hash}] author=org-c "
        f"parents={format_parents(result_c2.block.parents):16} "
        f'content="{result_c2.block.content}"'
    )
    print()

    # Report equivocation
    if result_c2.equivocation_detected:
        print("Equivocation detected:")
        b1, b2 = result_c2.conflicting_blocks
        print(f"  author:    {b1.author}")
        print(f'  block_1:   {b1.short_hash} (content="{b1.content}")')
        print(f'  block_2:   {b2.short_hash} (content="{b2.content}")')
        print(
            f"  evidence:  Blocks share parent [{result_a2.block.short_hash}] "
            "with no causal relationship"
        )
    print()

    print("Verification complete.")


def format_parents(parents: tuple[str, ...]) -> str:
    """Format parent hashes for display."""
    if not parents:
        return "[]"
    return "[" + ",".join(h[:8] for h in parents) + "]"


if __name__ == "__main__":
    main()
