"""Verification utilities for Blocklace A2A.

This module provides utilities for verifying blocks and detecting issues.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import UnknownAgentError, UnknownBlockError

if TYPE_CHECKING:
    from .blocklace import Blocklace
    from .types import Block

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of verifying a block or chain.

    Attributes:
        valid: Whether verification passed
        errors: List of error messages if invalid
        warnings: List of warning messages
    """

    valid: bool
    errors: list[str]
    warnings: list[str]

    @classmethod
    def success(cls, warnings: list[str] | None = None) -> VerificationResult:
        """Create a successful verification result."""
        return cls(valid=True, errors=[], warnings=warnings or [])

    @classmethod
    def failure(
        cls, errors: list[str], warnings: list[str] | None = None
    ) -> VerificationResult:
        """Create a failed verification result."""
        return cls(valid=False, errors=errors, warnings=warnings or [])


def verify_block(blocklace: Blocklace, block: Block) -> VerificationResult:
    """Verify a single block's integrity.

    Checks:
    - Hash matches content
    - Signature is valid
    - Author is registered
    - Parent blocks exist

    Args:
        blocklace: The blocklace containing the block
        block: The block to verify

    Returns:
        VerificationResult with status and any errors
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Check hash integrity
    if not block.verify_hash():
        errors.append(f"Block {block.short_hash}: hash mismatch")

    # Check author is registered
    try:
        public_key = blocklace.get_public_key(block.author)
    except UnknownAgentError:
        errors.append(f"Block {block.short_hash}: unknown author '{block.author}'")
        return VerificationResult.failure(errors, warnings)

    # Check signature
    if not block.verify(public_key):
        errors.append(f"Block {block.short_hash}: invalid signature")

    # Check parents exist
    for parent_hash in block.parents:
        try:
            blocklace.get_block(parent_hash)
        except UnknownBlockError:
            errors.append(f"Block {block.short_hash}: unknown parent {parent_hash[:8]}")

    if errors:
        return VerificationResult.failure(errors, warnings)
    return VerificationResult.success(warnings)


def verify_chain(blocklace: Blocklace) -> VerificationResult:
    """Verify the entire blocklace.

    Checks all blocks and detects any equivocations.

    Args:
        blocklace: The blocklace to verify

    Returns:
        VerificationResult with status and any errors/warnings
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Verify each block
    for block in blocklace.get_all_blocks():
        result = verify_block(blocklace, block)
        errors.extend(result.errors)
        warnings.extend(result.warnings)

    # Check for equivocations in each agent's blocks
    for agent_id in list(blocklace._agents.keys()):
        equivocations = blocklace.detect_equivocations(agent_id)
        for b1, b2 in equivocations:
            warnings.append(
                f"Equivocation by {agent_id}: "
                f"blocks {b1.short_hash} and {b2.short_hash}"
            )

    if errors:
        return VerificationResult.failure(errors, warnings)
    return VerificationResult.success(warnings)


def verify_message_integrity(
    blocklace: Blocklace,
    block_hash: str,
) -> VerificationResult:
    """Verify a specific message's integrity and chain of custody.

    Traces back through all ancestors to verify the complete history.

    Args:
        blocklace: The blocklace containing the message
        block_hash: Hash of the message block to verify

    Returns:
        VerificationResult with status and any errors
    """
    errors: list[str] = []
    warnings: list[str] = []
    verified: set[str] = set()

    try:
        target = blocklace.get_block(block_hash)
    except UnknownBlockError:
        return VerificationResult.failure([f"Block {block_hash[:8]} not found"])

    # BFS through ancestors
    queue = [target]
    while queue:
        block = queue.pop(0)
        if block.block_hash in verified:
            continue
        verified.add(block.block_hash)

        result = verify_block(blocklace, block)
        errors.extend(result.errors)
        warnings.extend(result.warnings)

        for parent_hash in block.parents:
            try:
                parent = blocklace.get_block(parent_hash)
                queue.append(parent)
            except UnknownBlockError:
                errors.append(f"Missing ancestor {parent_hash[:8]}")

    if errors:
        return VerificationResult.failure(errors, warnings)
    return VerificationResult.success(warnings)
