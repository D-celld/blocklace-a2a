"""Blocklace A2A: Cryptographic audit layer for A2A agent communication.

This package provides hash-chained, signed blocks with equivocation detection
for the A2A (Agent2Agent) protocol.

Example:
    >>> from blocklace_a2a import Blocklace, AgentId
    >>> lace = Blocklace()
    >>> keys = lace.register_agent(AgentId("org-a"))
    >>> result = lace.append(keys, "Hello from A")
    >>> print(result.block.short_hash)
"""

from .blocklace import Blocklace
from .exceptions import (
    BlocklaceError,
    EquivocationError,
    InvalidSignatureError,
    TamperError,
    UnknownAgentError,
    UnknownBlockError,
)
from .middleware import A2AMiddleware, MessageEnvelope, create_middleware
from .types import AgentId, AgentKeys, Block, WriteResult
from .verify import (
    VerificationResult,
    verify_block,
    verify_chain,
    verify_message_integrity,
)

__version__ = "0.1.0"

__all__ = [
    # Core
    "Blocklace",
    "Block",
    "AgentId",
    "AgentKeys",
    "WriteResult",
    # Middleware
    "A2AMiddleware",
    "MessageEnvelope",
    "create_middleware",
    # Verification
    "VerificationResult",
    "verify_block",
    "verify_chain",
    "verify_message_integrity",
    # Exceptions
    "BlocklaceError",
    "EquivocationError",
    "TamperError",
    "InvalidSignatureError",
    "UnknownAgentError",
    "UnknownBlockError",
]
