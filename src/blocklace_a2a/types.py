"""Core types for Blocklace A2A.

This module defines the fundamental data structures:
- AgentId: Unique identifier for an agent
- Block: A signed, hash-linked message in the DAG
- WriteResult: Result of appending a block to the blocklace
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, NewType

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Agent identifier (typically organization/agent name)
AgentId = NewType("AgentId", str)


def canonical_json(obj: dict[str, Any]) -> bytes:
    """Serialize object to canonical JSON (RFC 8785 approximation).

    Uses sorted keys and no whitespace for deterministic serialization.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Block:
    """A signed block in the blocklace DAG.

    Each block contains:
    - author: The agent that created this block
    - content: The message payload (any JSON-serializable data)
    - parents: Hash references to parent blocks (causally prior)
    - block_hash: SHA-256 hash of the block content
    - signature: Ed25519 signature over the hash
    """

    author: AgentId
    content: Any
    parents: tuple[str, ...]
    block_hash: str
    signature: bytes

    @classmethod
    def create(
        cls,
        author: AgentId,
        content: Any,
        parents: tuple[str, ...],
        private_key: Ed25519PrivateKey,
    ) -> Block:
        """Create a new signed block.

        Args:
            author: The agent creating this block
            content: Message payload (must be JSON-serializable)
            parents: Hashes of parent blocks
            private_key: Ed25519 private key for signing

        Returns:
            A new Block with computed hash and signature
        """
        # Compute hash over canonical representation
        hashable = {
            "author": author,
            "content": content,
            "parents": list(parents),
        }
        hash_input = canonical_json(hashable)
        block_hash = hashlib.sha256(hash_input).hexdigest()

        # Sign the hash
        signature = private_key.sign(block_hash.encode("utf-8"))

        return cls(
            author=author,
            content=content,
            parents=parents,
            block_hash=block_hash,
            signature=signature,
        )

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Verify the block's signature.

        Args:
            public_key: Ed25519 public key of the claimed author

        Returns:
            True if signature is valid

        Raises:
            InvalidSignatureError: If signature verification fails
        """
        try:
            public_key.verify(self.signature, self.block_hash.encode("utf-8"))
            return True
        except Exception:
            return False

    def verify_hash(self) -> bool:
        """Verify the block's hash matches its content.

        Returns:
            True if hash is valid
        """
        hashable = {
            "author": self.author,
            "content": self.content,
            "parents": list(self.parents),
        }
        hash_input = canonical_json(hashable)
        computed_hash = hashlib.sha256(hash_input).hexdigest()
        return computed_hash == self.block_hash

    @property
    def short_hash(self) -> str:
        """Return first 8 characters of hash for display."""
        return self.block_hash[:8]

    def to_dict(self) -> dict[str, Any]:
        """Serialize block to dictionary (for JSON output)."""
        return {
            "author": self.author,
            "content": self.content,
            "parents": list(self.parents),
            "hash": self.block_hash,
            "signature": self.signature.hex(),
        }


@dataclass
class WriteResult:
    """Result of appending a block to the blocklace.

    Attributes:
        block: The block that was appended
        equivocation_detected: Whether equivocation was detected
        conflicting_blocks: If equivocation detected, the conflicting blocks
    """

    block: Block
    equivocation_detected: bool = False
    conflicting_blocks: tuple[Block, Block] | None = None


@dataclass
class AgentKeys:
    """Cryptographic key pair for an agent.

    Attributes:
        agent_id: The agent's identifier
        private_key: Ed25519 private key for signing
        public_key: Ed25519 public key for verification
    """

    agent_id: AgentId
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey = field(init=False)

    def __post_init__(self) -> None:
        self.public_key = self.private_key.public_key()

    @classmethod
    def generate(cls, agent_id: AgentId) -> AgentKeys:
        """Generate a new key pair for an agent."""
        private_key = Ed25519PrivateKey.generate()
        return cls(agent_id=agent_id, private_key=private_key)

    @property
    def public_key_hex(self) -> str:
        """Return hex-encoded public key for display."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()[:8] + "..."
