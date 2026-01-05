"""Core Blocklace implementation.

The Blocklace is a DAG of signed, hash-linked blocks that provides:
- Tamper detection via hash chains
- Attribution via signatures
- Equivocation detection via DAG structure
- Causal ordering of messages
"""

from __future__ import annotations

import logging
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .exceptions import (
    InvalidSignatureError,
    TamperError,
    UnknownAgentError,
    UnknownBlockError,
)
from .types import AgentId, AgentKeys, Block, WriteResult

logger = logging.getLogger(__name__)


class Blocklace:
    """A DAG of signed, hash-linked blocks.

    The Blocklace provides cryptographic guarantees for agent communication:
    - Each block is signed by its author
    - Each block references its causal parents via hash
    - Equivocation (conflicting messages) is detectable

    Example:
        >>> lace = Blocklace()
        >>> keys = lace.register_agent(AgentId("org-a"))
        >>> result = lace.append(keys, "Hello from A", parents=())
        >>> print(result.block.short_hash)
    """

    def __init__(self) -> None:
        """Initialize an empty blocklace."""
        # Map from block hash to block
        self._blocks: dict[str, Block] = {}
        # Map from agent ID to public key
        self._agents: dict[AgentId, Ed25519PublicKey] = {}
        # Map from agent ID to list of their block hashes (in order)
        self._agent_blocks: dict[AgentId, list[str]] = {}
        # Set of known equivocations (for tracking)
        self._equivocations: set[tuple[str, str]] = set()

    def register_agent(self, agent_id: AgentId) -> AgentKeys:
        """Register a new agent and generate their key pair.

        Args:
            agent_id: Unique identifier for the agent

        Returns:
            AgentKeys containing the agent's key pair
        """
        keys = AgentKeys.generate(agent_id)
        self._agents[agent_id] = keys.public_key
        self._agent_blocks[agent_id] = []
        logger.info(f"Registered agent: {agent_id} (pk: {keys.public_key_hex})")
        return keys

    def register_agent_with_key(
        self, agent_id: AgentId, public_key: Ed25519PublicKey
    ) -> None:
        """Register an agent with an existing public key.

        Use this when the agent's key pair was generated elsewhere.

        Args:
            agent_id: Unique identifier for the agent
            public_key: The agent's Ed25519 public key
        """
        self._agents[agent_id] = public_key
        self._agent_blocks[agent_id] = []
        logger.info(f"Registered agent with existing key: {agent_id}")

    def get_public_key(self, agent_id: AgentId) -> Ed25519PublicKey:
        """Get the public key for an agent.

        Args:
            agent_id: The agent's identifier

        Returns:
            The agent's Ed25519 public key

        Raises:
            UnknownAgentError: If agent is not registered
        """
        if agent_id not in self._agents:
            raise UnknownAgentError(agent_id)
        return self._agents[agent_id]

    def append(
        self,
        keys: AgentKeys,
        content: Any,
        parents: tuple[str, ...] | None = None,
    ) -> WriteResult:
        """Append a new block to the blocklace.

        Args:
            keys: The agent's key pair (for signing)
            content: Message payload (must be JSON-serializable)
            parents: Hashes of parent blocks. If None, uses agent's latest block.

        Returns:
            WriteResult containing the new block and any equivocation info

        Raises:
            UnknownAgentError: If the agent is not registered
            UnknownBlockError: If a parent block doesn't exist
        """
        agent_id = keys.agent_id

        if agent_id not in self._agents:
            raise UnknownAgentError(agent_id)

        # Default to agent's latest block if no parents specified
        if parents is None:
            agent_chain = self._agent_blocks[agent_id]
            if agent_chain:
                parents = (agent_chain[-1],)
            else:
                parents = ()

        # Verify all parent blocks exist
        for parent_hash in parents:
            if parent_hash not in self._blocks:
                raise UnknownBlockError(parent_hash)

        # Create the block
        block = Block.create(
            author=agent_id,
            content=content,
            parents=parents,
            private_key=keys.private_key,
        )

        # Check for equivocation before adding
        equivocation = self._check_equivocation(block)

        # Add block to the DAG
        self._blocks[block.block_hash] = block
        self._agent_blocks[agent_id].append(block.block_hash)

        logger.info(
            f"Appended block: [{block.short_hash}] author={agent_id} "
            f"parents={[h[:8] for h in parents]} content={repr(content)[:50]}"
        )

        if equivocation:
            block1, block2 = equivocation
            self._equivocations.add((block1.block_hash, block2.block_hash))
            logger.warning(
                f"Equivocation detected: {agent_id} produced conflicting blocks "
                f"{block1.short_hash} and {block2.short_hash}"
            )
            return WriteResult(
                block=block,
                equivocation_detected=True,
                conflicting_blocks=(block1, block2),
            )

        return WriteResult(block=block)

    def _check_equivocation(self, new_block: Block) -> tuple[Block, Block] | None:
        """Check if the new block creates an equivocation.

        Equivocation occurs when the same author produces two blocks
        where neither is an ancestor of the other.

        Args:
            new_block: The block being added

        Returns:
            Tuple of conflicting blocks if equivocation detected, None otherwise
        """
        author = new_block.author
        author_blocks = self._agent_blocks.get(author, [])

        for existing_hash in author_blocks:
            existing = self._blocks[existing_hash]

            # Check if new_block is descendant of existing (OK)
            if self._is_ancestor(existing.block_hash, new_block):
                continue

            # Check if existing is descendant of new_block (OK)
            # This shouldn't happen in normal operation since we're adding new_block
            if self._is_ancestor(new_block.block_hash, existing):
                continue

            # Neither is ancestor of the other - equivocation!
            return (existing, new_block)

        return None

    def _is_ancestor(self, ancestor_hash: str, descendant: Block) -> bool:
        """Check if ancestor_hash is an ancestor of descendant block.

        Uses breadth-first search through parent links.

        Args:
            ancestor_hash: Hash of potential ancestor block
            descendant: The descendant block to check from

        Returns:
            True if ancestor_hash is in the ancestry of descendant
        """
        if ancestor_hash == descendant.block_hash:
            return True

        visited: set[str] = set()
        queue = list(descendant.parents)

        while queue:
            current_hash = queue.pop(0)
            if current_hash in visited:
                continue
            visited.add(current_hash)

            if current_hash == ancestor_hash:
                return True

            current_block = self._blocks.get(current_hash)
            if current_block:
                queue.extend(current_block.parents)

        return False

    def verify_block(self, block: Block) -> bool:
        """Verify a block's integrity and signature.

        Args:
            block: The block to verify

        Returns:
            True if block is valid

        Raises:
            TamperError: If hash doesn't match content
            InvalidSignatureError: If signature is invalid
            UnknownAgentError: If author is not registered
        """
        # Verify hash
        if not block.verify_hash():
            raise TamperError(block, "hash mismatch")

        # Get author's public key
        if block.author not in self._agents:
            raise UnknownAgentError(block.author)

        public_key = self._agents[block.author]

        # Verify signature
        if not block.verify(public_key):
            raise InvalidSignatureError(block)

        return True

    def get_block(self, block_hash: str) -> Block:
        """Get a block by its hash.

        Args:
            block_hash: The block's hash

        Returns:
            The block

        Raises:
            UnknownBlockError: If block doesn't exist
        """
        if block_hash not in self._blocks:
            raise UnknownBlockError(block_hash)
        return self._blocks[block_hash]

    def get_agent_blocks(self, agent_id: AgentId) -> list[Block]:
        """Get all blocks by an agent in order.

        Args:
            agent_id: The agent's identifier

        Returns:
            List of blocks by the agent

        Raises:
            UnknownAgentError: If agent is not registered
        """
        if agent_id not in self._agent_blocks:
            raise UnknownAgentError(agent_id)
        return [self._blocks[h] for h in self._agent_blocks[agent_id]]

    def detect_equivocations(self, agent_id: AgentId) -> list[tuple[Block, Block]]:
        """Detect all equivocations by an agent.

        Args:
            agent_id: The agent to check

        Returns:
            List of equivocating block pairs
        """
        if agent_id not in self._agent_blocks:
            raise UnknownAgentError(agent_id)

        equivocations: list[tuple[Block, Block]] = []
        blocks = self.get_agent_blocks(agent_id)

        for i, b1 in enumerate(blocks):
            for b2 in blocks[i + 1 :]:
                if not self._is_ancestor(b1.block_hash, b2) and not self._is_ancestor(
                    b2.block_hash, b1
                ):
                    equivocations.append((b1, b2))

        return equivocations

    @property
    def block_count(self) -> int:
        """Return total number of blocks."""
        return len(self._blocks)

    @property
    def agent_count(self) -> int:
        """Return number of registered agents."""
        return len(self._agents)

    def get_all_blocks(self) -> list[Block]:
        """Return all blocks in the blocklace."""
        return list(self._blocks.values())

    def get_tips(self) -> list[Block]:
        """Get all tip blocks (blocks with no children).

        Returns:
            List of blocks that are not referenced as parents by any other block
        """
        all_parents: set[str] = set()
        for block in self._blocks.values():
            all_parents.update(block.parents)

        tips = [
            block
            for block in self._blocks.values()
            if block.block_hash not in all_parents
        ]
        return tips
