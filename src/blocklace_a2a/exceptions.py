"""Custom exceptions for Blocklace A2A.

All exceptions inherit from BlocklaceError for easy catching.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .types import AgentId, Block


class BlocklaceError(Exception):
    """Base exception for all Blocklace errors."""

    pass


class EquivocationError(BlocklaceError):
    """Raised when equivocation is detected.

    Equivocation occurs when the same author produces two blocks
    where neither references the other as an ancestor.
    """

    def __init__(
        self,
        author: AgentId,
        block1: Block,
        block2: Block,
        message: str | None = None,
    ) -> None:
        self.author = author
        self.block1 = block1
        self.block2 = block2
        if message is None:
            message = (
                f"Equivocation detected for author '{author}': "
                f"blocks {block1.short_hash} and {block2.short_hash} "
                f"have no causal relationship"
            )
        super().__init__(message)


class TamperError(BlocklaceError):
    """Raised when tampering is detected.

    This occurs when:
    - A block's hash doesn't match its content
    - A block's signature is invalid
    - A block references non-existent parents
    """

    def __init__(
        self,
        block: Block,
        reason: str,
    ) -> None:
        self.block = block
        self.reason = reason
        message = f"Tamper detected in block {block.short_hash}: {reason}"
        super().__init__(message)


class InvalidSignatureError(BlocklaceError):
    """Raised when a signature verification fails."""

    def __init__(self, block: Block) -> None:
        self.block = block
        message = f"Invalid signature for block {block.short_hash}"
        super().__init__(message)


class UnknownAgentError(BlocklaceError):
    """Raised when an operation references an unknown agent."""

    def __init__(self, agent_id: AgentId) -> None:
        self.agent_id = agent_id
        message = f"Unknown agent: {agent_id}"
        super().__init__(message)


class UnknownBlockError(BlocklaceError):
    """Raised when a block references unknown parent blocks."""

    def __init__(self, block_hash: str) -> None:
        self.block_hash = block_hash
        message = f"Unknown block: {block_hash[:8]}"
        super().__init__(message)
