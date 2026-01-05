"""Test fixtures for Blocklace A2A."""

import pytest

from blocklace_a2a import AgentId, Blocklace


@pytest.fixture
def blocklace() -> Blocklace:
    """Create a fresh Blocklace instance."""
    return Blocklace()


@pytest.fixture
def agent_a_id() -> AgentId:
    """Agent ID for org-a."""
    return AgentId("org-a")


@pytest.fixture
def agent_b_id() -> AgentId:
    """Agent ID for org-b."""
    return AgentId("org-b")


@pytest.fixture
def agent_c_id() -> AgentId:
    """Agent ID for org-c."""
    return AgentId("org-c")


@pytest.fixture
def registered_agent_a(blocklace: Blocklace, agent_a_id: AgentId):
    """Register and return agent A's keys."""
    return blocklace.register_agent(agent_a_id)


@pytest.fixture
def registered_agent_b(blocklace: Blocklace, agent_b_id: AgentId):
    """Register and return agent B's keys."""
    return blocklace.register_agent(agent_b_id)


@pytest.fixture
def registered_agent_c(blocklace: Blocklace, agent_c_id: AgentId):
    """Register and return agent C's keys."""
    return blocklace.register_agent(agent_c_id)
