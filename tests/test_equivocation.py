"""Tests for equivocation detection (Byzantine scenario tests).

Equivocation occurs when the same author produces two blocks where
neither references the other as an ancestor. This is detected by
analyzing the DAG structure.
"""

from blocklace_a2a import AgentId, AgentKeys, Blocklace


class TestEquivocationDetection:
    """Tests for detecting equivocation."""

    def test_no_equivocation_linear_chain(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Linear chain of blocks has no equivocation."""
        r1 = blocklace.append(registered_agent_a, "First")
        r2 = blocklace.append(registered_agent_a, "Second")
        r3 = blocklace.append(registered_agent_a, "Third")

        assert r1.equivocation_detected is False
        assert r2.equivocation_detected is False
        assert r3.equivocation_detected is False

    def test_no_equivocation_merging_branches(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
    ):
        """Different agents can have separate branches without equivocation."""
        ra = blocklace.append(registered_agent_a, "From A")
        rb = blocklace.append(registered_agent_b, "From B")

        # Both reference nothing as parent (they're concurrent)
        # This is fine for different agents
        assert ra.equivocation_detected is False
        assert rb.equivocation_detected is False

    def test_equivocation_same_parent(
        self, blocklace: Blocklace, registered_agent_c: AgentKeys, agent_c_id: AgentId
    ):
        """Same agent creating two blocks with same parent is equivocation."""
        # Create a base block
        base = blocklace.append(registered_agent_c, "Base")

        # First block referencing base
        result1 = blocklace.append(
            registered_agent_c, "Approved: $100", parents=(base.block.block_hash,)
        )
        assert result1.equivocation_detected is False

        # Second block also referencing base (not referencing result1)
        # This creates an equivocation
        result2 = blocklace.append(
            registered_agent_c, "Approved: $999", parents=(base.block.block_hash,)
        )
        assert result2.equivocation_detected is True
        assert result2.conflicting_blocks is not None

        # The conflicting blocks should be result1 and result2
        b1, b2 = result2.conflicting_blocks
        assert {b1.content, b2.content} == {"Approved: $100", "Approved: $999"}

    def test_equivocation_no_common_ancestor(
        self, blocklace: Blocklace, registered_agent_c: AgentKeys
    ):
        """Two blocks with no parents from same agent is equivocation."""
        # First block with no parents
        blocklace.append(registered_agent_c, "Message 1", parents=())

        # Second block with no parents (not referencing first)
        r2 = blocklace.append(registered_agent_c, "Message 2", parents=())

        assert r2.equivocation_detected is True

    def test_detect_equivocations_method(
        self, blocklace: Blocklace, registered_agent_c: AgentKeys, agent_c_id: AgentId
    ):
        """detect_equivocations returns all equivocating pairs."""
        # Create equivocation
        blocklace.append(registered_agent_c, "M1", parents=())
        blocklace.append(registered_agent_c, "M2", parents=())
        blocklace.append(registered_agent_c, "M3", parents=())

        equivocations = blocklace.detect_equivocations(agent_c_id)

        # With 3 blocks with no ancestry, we have 3 pairs: (1,2), (1,3), (2,3)
        assert len(equivocations) == 3

    def test_no_equivocation_proper_chain(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys, agent_a_id: AgentId
    ):
        """Proper chain has no equivocations."""
        blocklace.append(registered_agent_a, "M1")
        blocklace.append(registered_agent_a, "M2")  # Auto-parents to M1
        blocklace.append(registered_agent_a, "M3")  # Auto-parents to M2

        equivocations = blocklace.detect_equivocations(agent_a_id)
        assert len(equivocations) == 0


class TestEquivocationScenarios:
    """Real-world equivocation scenarios."""

    def test_double_spend_scenario(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
        registered_agent_c: AgentKeys,
    ):
        """
        Scenario: Agent C tries to approve different amounts to A and B.

        Timeline:
        1. A sends request to C
        2. C sends "Approved $100" to A
        3. C sends "Approved $999" to B (equivocation!)
        """
        # A sends request
        req = blocklace.append(registered_agent_a, {"type": "request", "amount": 100})

        # C approves to A
        approve_a = blocklace.append(
            registered_agent_c,
            {"type": "approval", "amount": 100, "to": "org-a"},
            parents=(req.block.block_hash,),
        )
        assert approve_a.equivocation_detected is False

        # C tries to approve different amount (equivocation)
        approve_b = blocklace.append(
            registered_agent_c,
            {"type": "approval", "amount": 999, "to": "org-b"},
            parents=(req.block.block_hash,),
        )
        assert approve_b.equivocation_detected is True

    def test_conflicting_orders_scenario(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
        registered_agent_c: AgentKeys,
    ):
        """
        Scenario: Agent C gives conflicting orders to A and B.

        This is detected because both orders have the same parent
        but neither references the other.
        """
        # Initial state
        init = blocklace.append(registered_agent_c, "Initialize")

        # Order to A
        blocklace.append(
            registered_agent_c,
            {"order": "sell", "agent": "A"},
            parents=(init.block.block_hash,),
        )

        # Conflicting order to B
        order_b = blocklace.append(
            registered_agent_c,
            {"order": "buy", "agent": "B"},
            parents=(init.block.block_hash,),
        )

        assert order_b.equivocation_detected is True
        b1, b2 = order_b.conflicting_blocks
        assert b1.content["order"] != b2.content["order"]

    def test_honest_broadcast_no_equivocation(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
        registered_agent_c: AgentKeys,
    ):
        """
        Scenario: Agent C honestly broadcasts same message to multiple agents.

        By properly chaining messages, no equivocation occurs.
        """
        # C broadcasts to A
        to_a = blocklace.append(
            registered_agent_c,
            {"broadcast": "System update at 5pm", "to": "A"},
        )

        # C broadcasts to B, referencing previous message
        to_b = blocklace.append(
            registered_agent_c,
            {"broadcast": "System update at 5pm", "to": "B"},
            parents=(to_a.block.block_hash,),
        )

        assert to_a.equivocation_detected is False
        assert to_b.equivocation_detected is False


class TestAncestryChecking:
    """Tests for the ancestry checking logic."""

    def test_direct_parent_is_ancestor(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Direct parent is considered an ancestor."""
        blocklace.append(registered_agent_a, "First")
        result = blocklace.append(registered_agent_a, "Second")

        # First block is direct parent of result, so result is not equivocation
        assert result.equivocation_detected is False

    def test_grandparent_is_ancestor(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Grandparent is also considered an ancestor."""
        blocklace.append(registered_agent_a, "First")
        blocklace.append(registered_agent_a, "Second")
        result = blocklace.append(registered_agent_a, "Third")

        # All in proper chain
        assert result.equivocation_detected is False

    def test_sibling_not_ancestor(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Blocks that are siblings (same parent) have no ancestry relation."""
        base = blocklace.append(registered_agent_a, "Base")

        # Two siblings
        blocklace.append(
            registered_agent_a, "Sibling 1", parents=(base.block.block_hash,)
        )
        sibling2 = blocklace.append(
            registered_agent_a, "Sibling 2", parents=(base.block.block_hash,)
        )

        # sibling2 should detect equivocation with first sibling
        assert sibling2.equivocation_detected is True
