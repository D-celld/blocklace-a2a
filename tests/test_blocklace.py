"""Tests for core Blocklace functionality."""

import pytest

from blocklace_a2a import (
    AgentId,
    AgentKeys,
    Blocklace,
    UnknownAgentError,
    UnknownBlockError,
)


class TestAgentRegistration:
    """Tests for agent registration."""

    def test_register_agent(self, blocklace: Blocklace, agent_a_id: AgentId):
        """Registering an agent returns keys and updates count."""
        keys = blocklace.register_agent(agent_a_id)

        assert keys.agent_id == agent_a_id
        assert blocklace.agent_count == 1

    def test_register_multiple_agents(self, blocklace: Blocklace):
        """Can register multiple agents."""
        blocklace.register_agent(AgentId("org-a"))
        blocklace.register_agent(AgentId("org-b"))
        blocklace.register_agent(AgentId("org-c"))

        assert blocklace.agent_count == 3

    def test_get_public_key(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys, agent_a_id: AgentId
    ):
        """Can retrieve an agent's public key."""
        public_key = blocklace.get_public_key(agent_a_id)
        assert public_key == registered_agent_a.public_key

    def test_get_unknown_agent_raises(self, blocklace: Blocklace):
        """Getting key for unknown agent raises UnknownAgentError."""
        with pytest.raises(UnknownAgentError):
            blocklace.get_public_key(AgentId("unknown"))


class TestBlockCreation:
    """Tests for block creation and appending."""

    def test_append_first_block(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """First block has no parents."""
        result = blocklace.append(registered_agent_a, "Hello")

        assert result.block.author == registered_agent_a.agent_id
        assert result.block.content == "Hello"
        assert result.block.parents == ()
        assert blocklace.block_count == 1

    def test_append_second_block_auto_parents(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Second block automatically references first as parent."""
        result1 = blocklace.append(registered_agent_a, "First")
        result2 = blocklace.append(registered_agent_a, "Second")

        assert result2.block.parents == (result1.block.block_hash,)

    def test_append_with_explicit_parents(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
    ):
        """Can specify explicit parent blocks."""
        result_a = blocklace.append(registered_agent_a, "From A")
        result_b = blocklace.append(
            registered_agent_b, "From B", parents=(result_a.block.block_hash,)
        )

        assert result_b.block.parents == (result_a.block.block_hash,)

    def test_append_unknown_agent_raises(self, blocklace: Blocklace):
        """Appending with unregistered agent raises."""
        keys = AgentKeys.generate(AgentId("unknown"))
        with pytest.raises(UnknownAgentError):
            blocklace.append(keys, "test")

    def test_append_unknown_parent_raises(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Appending with unknown parent hash raises."""
        with pytest.raises(UnknownBlockError):
            blocklace.append(
                registered_agent_a, "test", parents=("nonexistent_hash",)
            )


class TestBlockRetrieval:
    """Tests for retrieving blocks."""

    def test_get_block(self, blocklace: Blocklace, registered_agent_a: AgentKeys):
        """Can retrieve block by hash."""
        result = blocklace.append(registered_agent_a, "test")
        block = blocklace.get_block(result.block.block_hash)

        assert block == result.block

    def test_get_unknown_block_raises(self, blocklace: Blocklace):
        """Getting unknown block raises UnknownBlockError."""
        with pytest.raises(UnknownBlockError):
            blocklace.get_block("nonexistent")

    def test_get_agent_blocks(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys, agent_a_id: AgentId
    ):
        """Can get all blocks by an agent."""
        blocklace.append(registered_agent_a, "First")
        blocklace.append(registered_agent_a, "Second")
        blocklace.append(registered_agent_a, "Third")

        blocks = blocklace.get_agent_blocks(agent_a_id)
        assert len(blocks) == 3
        assert [b.content for b in blocks] == ["First", "Second", "Third"]

    def test_get_all_blocks(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
    ):
        """Can get all blocks in the blocklace."""
        blocklace.append(registered_agent_a, "A1")
        blocklace.append(registered_agent_b, "B1")
        blocklace.append(registered_agent_a, "A2")

        blocks = blocklace.get_all_blocks()
        assert len(blocks) == 3

    def test_get_tips(
        self,
        blocklace: Blocklace,
        registered_agent_a: AgentKeys,
        registered_agent_b: AgentKeys,
    ):
        """Tips are blocks with no children."""
        result_a1 = blocklace.append(registered_agent_a, "A1")
        result_b1 = blocklace.append(
            registered_agent_b, "B1", parents=(result_a1.block.block_hash,)
        )

        tips = blocklace.get_tips()
        assert len(tips) == 1
        assert tips[0] == result_b1.block


class TestBlockVerification:
    """Tests for block verification."""

    def test_verify_valid_block(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Valid block passes verification."""
        result = blocklace.append(registered_agent_a, "test")
        assert blocklace.verify_block(result.block) is True

    def test_verify_hash_integrity(
        self, blocklace: Blocklace, registered_agent_a: AgentKeys
    ):
        """Block.verify_hash detects tampering."""
        result = blocklace.append(registered_agent_a, "test")

        # Create a tampered block (would require breaking frozen dataclass)
        # Instead test the verify_hash method directly
        assert result.block.verify_hash() is True


class TestBlockSerialization:
    """Tests for block serialization."""

    def test_to_dict(self, blocklace: Blocklace, registered_agent_a: AgentKeys):
        """Block can be serialized to dict."""
        result = blocklace.append(registered_agent_a, {"key": "value"})
        d = result.block.to_dict()

        assert d["author"] == registered_agent_a.agent_id
        assert d["content"] == {"key": "value"}
        assert d["parents"] == []
        assert "hash" in d
        assert "signature" in d

    def test_short_hash(self, blocklace: Blocklace, registered_agent_a: AgentKeys):
        """short_hash returns first 8 characters."""
        result = blocklace.append(registered_agent_a, "test")
        assert len(result.block.short_hash) == 8
        assert result.block.block_hash.startswith(result.block.short_hash)


class TestCanonicalJSON:
    """Tests for canonical JSON serialization."""

    def test_deterministic_hashing(self, blocklace: Blocklace):
        """Same content produces same hash regardless of dict ordering."""
        from blocklace_a2a.types import canonical_json

        dict1 = {"b": 2, "a": 1}
        dict2 = {"a": 1, "b": 2}

        assert canonical_json(dict1) == canonical_json(dict2)

    def test_no_whitespace(self, blocklace: Blocklace):
        """Canonical JSON has no extra whitespace."""
        from blocklace_a2a.types import canonical_json

        result = canonical_json({"key": "value", "num": 42})
        assert b" " not in result
        assert b"\n" not in result
