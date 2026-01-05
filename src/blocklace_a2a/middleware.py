"""A2A Integration Middleware.

This module provides middleware that wraps A2A message passing to add
Blocklace cryptographic guarantees. It intercepts send/receive operations
to log messages to the Blocklace and verify incoming messages.

The middleware:
- Does NOT modify A2A transport (HTTP, JSON-RPC, SSE)
- Does NOT replace OAuth/JWT/TLS
- Complements existing A2A security with tamper-proof audit trail
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .blocklace import Blocklace
from .exceptions import EquivocationError
from .types import AgentId, AgentKeys, Block
from .verify import VerificationResult

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class MessageEnvelope:
    """Wrapper for A2A messages with Blocklace metadata.

    This envelope is attached to messages to provide cryptographic proof
    of the message's origin and ordering.

    Attributes:
        content: The original message content
        block_hash: Hash of the Blocklace block containing this message
        signature: Hex-encoded signature
        parents: Hashes of parent blocks (for verification)
        author: Agent ID of the sender
    """

    content: Any
    block_hash: str
    signature: str
    parents: list[str]
    author: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for transport."""
        return {
            "content": self.content,
            "block_hash": self.block_hash,
            "signature": self.signature,
            "parents": self.parents,
            "author": self.author,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessageEnvelope:
        """Deserialize from dictionary."""
        return cls(
            content=data["content"],
            block_hash=data["block_hash"],
            signature=data["signature"],
            parents=data["parents"],
            author=data["author"],
        )

    @classmethod
    def from_block(cls, block: Block) -> MessageEnvelope:
        """Create envelope from a Blocklace block."""
        return cls(
            content=block.content,
            block_hash=block.block_hash,
            signature=block.signature.hex(),
            parents=list(block.parents),
            author=block.author,
        )


@dataclass
class A2AMiddleware:
    """Middleware for adding Blocklace to A2A communication.

    This middleware wraps message send/receive operations to:
    1. Log all outgoing messages to the Blocklace
    2. Verify incoming messages against the ledger
    3. Detect equivocation attempts

    Example:
        >>> blocklace = Blocklace()
        >>> keys = blocklace.register_agent(AgentId("my-agent"))
        >>> middleware = A2AMiddleware(blocklace, keys)
        >>>
        >>> # Wrap outgoing message
        >>> envelope = middleware.wrap_outgoing({"type": "request", "data": "..."})
        >>>
        >>> # Verify incoming message
        >>> result = middleware.verify_incoming(envelope)
        >>> if not result.valid:
        >>>     raise SecurityError(result.errors)
    """

    blocklace: Blocklace
    agent_keys: AgentKeys
    on_equivocation: Callable[[EquivocationError], None] | None = None
    strict_mode: bool = True
    _last_block_hash: str | None = field(default=None, init=False)

    def wrap_outgoing(
        self,
        content: Any,
        parents: tuple[str, ...] | None = None,
    ) -> MessageEnvelope:
        """Wrap an outgoing message with Blocklace proof.

        Creates a new block in the Blocklace and returns an envelope
        containing the message with cryptographic metadata.

        Args:
            content: The message to send (must be JSON-serializable)
            parents: Optional explicit parent block hashes

        Returns:
            MessageEnvelope ready for transport
        """
        result = self.blocklace.append(
            self.agent_keys,
            content,
            parents=parents,
        )
        self._last_block_hash = result.block.block_hash

        envelope = MessageEnvelope.from_block(result.block)

        logger.info(
            f"Wrapped outgoing message: {result.block.short_hash} "
            f"content={repr(content)[:50]}"
        )

        return envelope

    def verify_incoming(
        self,
        envelope: MessageEnvelope,
    ) -> VerificationResult:
        """Verify an incoming message envelope.

        Checks:
        - The claimed author is registered
        - The block hash is valid
        - The signature is valid
        - No equivocation detected

        Args:
            envelope: The received message envelope

        Returns:
            VerificationResult with validation status
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Reconstruct block from envelope
        author = AgentId(envelope.author)

        # Check author is known
        try:
            public_key = self.blocklace.get_public_key(author)
        except Exception:
            errors.append(f"Unknown sender: {envelope.author}")
            return VerificationResult.failure(errors, warnings)

        # Reconstruct the block for verification
        try:
            signature = bytes.fromhex(envelope.signature)
        except ValueError:
            errors.append("Invalid signature format")
            return VerificationResult.failure(errors, warnings)

        block = Block(
            author=author,
            content=envelope.content,
            parents=tuple(envelope.parents),
            block_hash=envelope.block_hash,
            signature=signature,
        )

        # Verify hash
        if not block.verify_hash():
            errors.append("Block hash mismatch - message may be tampered")
            return VerificationResult.failure(errors, warnings)

        # Verify signature
        if not block.verify(public_key):
            errors.append("Invalid signature - message authenticity unverified")
            return VerificationResult.failure(errors, warnings)

        # Add block to local ledger and check for equivocation
        # Note: We register with existing public key to accept the block
        if author not in self.blocklace._agents:
            self.blocklace.register_agent_with_key(author, public_key)

        # Check if all parents exist (may not for first contact)
        missing_parents = [
            p for p in envelope.parents
            if p not in self.blocklace._blocks
        ]
        if missing_parents:
            warnings.append(
                f"Missing parent blocks: {[h[:8] for h in missing_parents]}. "
                "Cannot fully verify causal chain."
            )

        # Add block and check equivocation
        if block.block_hash not in self.blocklace._blocks:
            self.blocklace._blocks[block.block_hash] = block
            self.blocklace._agent_blocks.setdefault(author, []).append(block.block_hash)

            # Check for equivocation
            equivocations = self.blocklace.detect_equivocations(author)
            if equivocations:
                eq_error = EquivocationError(
                    author=author,
                    block1=equivocations[0][0],
                    block2=equivocations[0][1],
                )
                if self.on_equivocation:
                    self.on_equivocation(eq_error)
                warnings.append(str(eq_error))

        logger.info(
            f"Verified incoming message: {block.short_hash} from {author}"
        )

        if errors:
            return VerificationResult.failure(errors, warnings)
        return VerificationResult.success(warnings)

    def get_last_block_hash(self) -> str | None:
        """Get the hash of the last block this agent created.

        Useful for specifying parents in multi-party conversations.
        """
        return self._last_block_hash

    def get_audit_trail(self, block_hash: str) -> list[Block]:
        """Get the complete audit trail for a message.

        Returns all ancestor blocks in causal order.

        Args:
            block_hash: Hash of the message to trace

        Returns:
            List of blocks from oldest ancestor to the specified message
        """
        trail: list[Block] = []
        visited: set[str] = set()

        def traverse(hash_: str) -> None:
            if hash_ in visited:
                return
            visited.add(hash_)

            try:
                block = self.blocklace.get_block(hash_)
            except Exception:
                return

            for parent in block.parents:
                traverse(parent)

            trail.append(block)

        traverse(block_hash)
        return trail


def create_middleware(
    blocklace: Blocklace,
    agent_id: str,
    on_equivocation: Callable[[EquivocationError], None] | None = None,
) -> A2AMiddleware:
    """Create a new middleware instance for an agent.

    Convenience function that registers the agent and creates middleware.

    Args:
        blocklace: The shared Blocklace instance
        agent_id: Identifier for this agent
        on_equivocation: Optional callback for equivocation events

    Returns:
        Configured A2AMiddleware instance
    """
    keys = blocklace.register_agent(AgentId(agent_id))
    return A2AMiddleware(
        blocklace=blocklace,
        agent_keys=keys,
        on_equivocation=on_equivocation,
    )
