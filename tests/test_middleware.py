"""Tests for A2A middleware integration."""

from blocklace_a2a import (
    A2AMiddleware,
    AgentId,
    Blocklace,
    EquivocationError,
    MessageEnvelope,
    create_middleware,
    verify_block,
    verify_chain,
    verify_message_integrity,
)


class TestMessageEnvelope:
    """Tests for MessageEnvelope serialization."""

    def test_to_dict(self, blocklace: Blocklace, registered_agent_a):
        """Envelope can be serialized to dict."""
        middleware = A2AMiddleware(blocklace, registered_agent_a)
        envelope = middleware.wrap_outgoing({"type": "test"})

        d = envelope.to_dict()
        assert d["content"] == {"type": "test"}
        assert "block_hash" in d
        assert "signature" in d
        assert "parents" in d
        assert d["author"] == registered_agent_a.agent_id

    def test_from_dict(self, blocklace: Blocklace, registered_agent_a):
        """Envelope can be deserialized from dict."""
        middleware = A2AMiddleware(blocklace, registered_agent_a)
        envelope = middleware.wrap_outgoing("test message")

        d = envelope.to_dict()
        restored = MessageEnvelope.from_dict(d)

        assert restored.content == envelope.content
        assert restored.block_hash == envelope.block_hash
        assert restored.signature == envelope.signature
        assert restored.author == envelope.author

    def test_roundtrip_json(self, blocklace: Blocklace, registered_agent_a):
        """Envelope survives JSON roundtrip."""
        import json

        middleware = A2AMiddleware(blocklace, registered_agent_a)
        envelope = middleware.wrap_outgoing({"key": "value", "num": 42})

        json_str = json.dumps(envelope.to_dict())
        restored = MessageEnvelope.from_dict(json.loads(json_str))

        assert restored.content == envelope.content
        assert restored.block_hash == envelope.block_hash


class TestMiddlewareWrapOutgoing:
    """Tests for wrapping outgoing messages."""

    def test_wrap_creates_block(self, blocklace: Blocklace, registered_agent_a):
        """Wrapping message creates block in blocklace."""
        middleware = A2AMiddleware(blocklace, registered_agent_a)

        assert blocklace.block_count == 0
        middleware.wrap_outgoing("test")
        assert blocklace.block_count == 1

    def test_wrap_auto_chains(self, blocklace: Blocklace, registered_agent_a):
        """Multiple wraps create a chain."""
        middleware = A2AMiddleware(blocklace, registered_agent_a)

        env1 = middleware.wrap_outgoing("first")
        env2 = middleware.wrap_outgoing("second")

        assert env2.parents == [env1.block_hash]

    def test_wrap_with_explicit_parents(
        self,
        blocklace: Blocklace,
        registered_agent_a,
        registered_agent_b,
    ):
        """Can specify explicit parents for merge points."""
        mw_a = A2AMiddleware(blocklace, registered_agent_a)
        mw_b = A2AMiddleware(blocklace, registered_agent_b)

        env_a = mw_a.wrap_outgoing("from A")
        env_b = mw_b.wrap_outgoing("from B", parents=(env_a.block_hash,))

        assert env_b.parents == [env_a.block_hash]

    def test_get_last_block_hash(self, blocklace: Blocklace, registered_agent_a):
        """Can retrieve last block hash."""
        middleware = A2AMiddleware(blocklace, registered_agent_a)

        assert middleware.get_last_block_hash() is None
        env = middleware.wrap_outgoing("test")
        assert middleware.get_last_block_hash() == env.block_hash


class TestMiddlewareVerifyIncoming:
    """Tests for verifying incoming messages."""

    def test_verify_valid_message(
        self,
        blocklace: Blocklace,
        registered_agent_a,
        registered_agent_b,
    ):
        """Valid message passes verification."""
        mw_sender = A2AMiddleware(blocklace, registered_agent_a)
        mw_receiver = A2AMiddleware(blocklace, registered_agent_b)

        envelope = mw_sender.wrap_outgoing("hello")
        result = mw_receiver.verify_incoming(envelope)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_verify_unknown_sender(self, blocklace: Blocklace, registered_agent_a):
        """Message from unknown sender fails verification."""
        # Create a separate blocklace with unknown agent
        other_lace = Blocklace()
        unknown_keys = other_lace.register_agent(AgentId("unknown-org"))
        unknown_mw = A2AMiddleware(other_lace, unknown_keys)

        envelope = unknown_mw.wrap_outgoing("hello")

        # Try to verify in original blocklace
        receiver_mw = A2AMiddleware(blocklace, registered_agent_a)
        result = receiver_mw.verify_incoming(envelope)

        assert result.valid is False
        assert any("Unknown sender" in e for e in result.errors)

    def test_verify_tampered_content(
        self,
        blocklace: Blocklace,
        registered_agent_a,
        registered_agent_b,
    ):
        """Tampered message fails verification."""
        mw_sender = A2AMiddleware(blocklace, registered_agent_a)
        mw_receiver = A2AMiddleware(blocklace, registered_agent_b)

        envelope = mw_sender.wrap_outgoing("original")

        # Tamper with content
        tampered = MessageEnvelope(
            content="tampered",  # Changed!
            block_hash=envelope.block_hash,
            signature=envelope.signature,
            parents=envelope.parents,
            author=envelope.author,
        )

        result = mw_receiver.verify_incoming(tampered)
        assert result.valid is False
        assert any("tampered" in e.lower() for e in result.errors)

    def test_verify_invalid_signature(
        self,
        blocklace: Blocklace,
        registered_agent_a,
        registered_agent_b,
    ):
        """Invalid signature fails verification."""
        mw_sender = A2AMiddleware(blocklace, registered_agent_a)
        mw_receiver = A2AMiddleware(blocklace, registered_agent_b)

        envelope = mw_sender.wrap_outgoing("test")

        # Create fake signature
        fake_sig = "00" * 64  # 64-byte zero signature

        tampered = MessageEnvelope(
            content=envelope.content,
            block_hash=envelope.block_hash,
            signature=fake_sig,
            parents=envelope.parents,
            author=envelope.author,
        )

        result = mw_receiver.verify_incoming(tampered)
        assert result.valid is False

    def test_verify_detects_equivocation(
        self,
        blocklace: Blocklace,
        registered_agent_a,
        registered_agent_c,
    ):
        """Verification detects equivocation from remote agent."""
        # Simulate remote agent creating equivocating messages
        remote_lace = Blocklace()
        remote_keys = remote_lace.register_agent(AgentId("org-c"))
        remote_mw = A2AMiddleware(remote_lace, remote_keys)

        # Remote agent creates base and two conflicting messages
        base = remote_mw.wrap_outgoing("base")
        msg1 = remote_mw.wrap_outgoing("approved $100", parents=(base.block_hash,))
        msg2 = remote_mw.wrap_outgoing("approved $999", parents=(base.block_hash,))

        # Local receiver
        local_mw = A2AMiddleware(blocklace, registered_agent_a)

        # Register the remote agent's key locally
        blocklace.register_agent_with_key(
            AgentId("org-c"), remote_keys.public_key
        )

        # Receive base and first message
        local_mw.verify_incoming(base)
        local_mw.verify_incoming(msg1)

        # Receiving second conflicting message should warn about equivocation
        result = local_mw.verify_incoming(msg2)
        assert any("quivocation" in w for w in result.warnings)


class TestMiddlewareEquivocationCallback:
    """Tests for equivocation callback handling."""

    def test_callback_invoked_on_incoming(
        self, blocklace: Blocklace, registered_agent_a
    ):
        """Equivocation callback is invoked when receiving conflicting messages."""
        equivocations_detected: list[EquivocationError] = []

        def on_equivocation(err: EquivocationError) -> None:
            equivocations_detected.append(err)

        # Simulate remote agent creating equivocating messages
        remote_lace = Blocklace()
        remote_keys = remote_lace.register_agent(AgentId("remote"))
        remote_mw = A2AMiddleware(remote_lace, remote_keys)

        base = remote_mw.wrap_outgoing("base")
        msg1 = remote_mw.wrap_outgoing("msg1", parents=(base.block_hash,))
        msg2 = remote_mw.wrap_outgoing("msg2", parents=(base.block_hash,))

        # Local receiver with callback
        blocklace.register_agent_with_key(AgentId("remote"), remote_keys.public_key)
        local_mw = A2AMiddleware(
            blocklace, registered_agent_a, on_equivocation=on_equivocation
        )

        # Receive messages - equivocation should trigger callback
        local_mw.verify_incoming(base)
        local_mw.verify_incoming(msg1)
        local_mw.verify_incoming(msg2)

        # Callback should have been invoked
        assert len(equivocations_detected) >= 1


class TestMiddlewareAuditTrail:
    """Tests for audit trail functionality."""

    def test_get_audit_trail_single(
        self, blocklace: Blocklace, registered_agent_a
    ):
        """Audit trail for single message includes just that message."""
        mw = A2AMiddleware(blocklace, registered_agent_a)
        env = mw.wrap_outgoing("test")

        trail = mw.get_audit_trail(env.block_hash)
        assert len(trail) == 1
        assert trail[0].content == "test"

    def test_get_audit_trail_chain(
        self, blocklace: Blocklace, registered_agent_a
    ):
        """Audit trail includes all ancestors in order."""
        mw = A2AMiddleware(blocklace, registered_agent_a)

        mw.wrap_outgoing("first")
        mw.wrap_outgoing("second")
        env = mw.wrap_outgoing("third")

        trail = mw.get_audit_trail(env.block_hash)
        assert len(trail) == 3
        assert [b.content for b in trail] == ["first", "second", "third"]

    def test_get_audit_trail_multiparty(
        self,
        blocklace: Blocklace,
        registered_agent_a,
        registered_agent_b,
    ):
        """Audit trail works across multiple agents."""
        mw_a = A2AMiddleware(blocklace, registered_agent_a)
        mw_b = A2AMiddleware(blocklace, registered_agent_b)

        env_a1 = mw_a.wrap_outgoing("A says hello")
        env_b1 = mw_b.wrap_outgoing("B replies", parents=(env_a1.block_hash,))
        env_a2 = mw_a.wrap_outgoing("A responds", parents=(env_b1.block_hash,))

        trail = mw_a.get_audit_trail(env_a2.block_hash)
        assert len(trail) == 3
        assert trail[0].author == "org-a"
        assert trail[1].author == "org-b"
        assert trail[2].author == "org-a"


class TestCreateMiddleware:
    """Tests for create_middleware convenience function."""

    def test_create_middleware(self, blocklace: Blocklace):
        """create_middleware registers agent and creates middleware."""
        mw = create_middleware(blocklace, "new-agent")

        assert blocklace.agent_count == 1
        assert mw.agent_keys.agent_id == AgentId("new-agent")

    def test_create_middleware_with_callback(self, blocklace: Blocklace):
        """create_middleware accepts callback and detects incoming equivocation."""
        errors: list[EquivocationError] = []
        mw = create_middleware(
            blocklace, "local-agent", on_equivocation=lambda e: errors.append(e)
        )

        # Simulate remote agent creating equivocating messages
        remote_lace = Blocklace()
        remote_keys = remote_lace.register_agent(AgentId("remote"))
        remote_mw = A2AMiddleware(remote_lace, remote_keys)

        base = remote_mw.wrap_outgoing("base")
        msg1 = remote_mw.wrap_outgoing("a", parents=(base.block_hash,))
        msg2 = remote_mw.wrap_outgoing("b", parents=(base.block_hash,))

        # Register remote agent and receive messages
        blocklace.register_agent_with_key(AgentId("remote"), remote_keys.public_key)
        mw.verify_incoming(base)
        mw.verify_incoming(msg1)
        mw.verify_incoming(msg2)

        assert len(errors) >= 1


class TestVerificationUtilities:
    """Tests for verification utility functions."""

    def test_verify_block_valid(
        self, blocklace: Blocklace, registered_agent_a
    ):
        """verify_block passes for valid block."""
        result = blocklace.append(registered_agent_a, "test")
        verification = verify_block(blocklace, result.block)

        assert verification.valid is True

    def test_verify_chain_valid(
        self, blocklace: Blocklace, registered_agent_a, registered_agent_b
    ):
        """verify_chain passes for valid chain."""
        blocklace.append(registered_agent_a, "A1")
        result_b = blocklace.append(registered_agent_b, "B1")
        blocklace.append(
            registered_agent_a, "A2", parents=(result_b.block.block_hash,)
        )

        verification = verify_chain(blocklace)
        assert verification.valid is True

    def test_verify_chain_detects_equivocation(
        self, blocklace: Blocklace, registered_agent_a
    ):
        """verify_chain includes equivocation warnings."""
        base = blocklace.append(registered_agent_a, "base")
        blocklace.append(
            registered_agent_a, "m1", parents=(base.block.block_hash,)
        )
        blocklace.append(
            registered_agent_a, "m2", parents=(base.block.block_hash,)
        )

        verification = verify_chain(blocklace)
        # Should have warnings about equivocation
        assert any("quivocation" in w for w in verification.warnings)

    def test_verify_message_integrity(
        self, blocklace: Blocklace, registered_agent_a
    ):
        """verify_message_integrity traces full ancestry."""
        blocklace.append(registered_agent_a, "first")
        blocklace.append(registered_agent_a, "second")
        result = blocklace.append(registered_agent_a, "third")

        verification = verify_message_integrity(blocklace, result.block.block_hash)
        assert verification.valid is True
