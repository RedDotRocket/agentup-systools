"""Tests for Agentup Systools plugin."""

import pytest
from agent.plugins.models import CapabilityContext
from agentup_systools.plugin import AgentupSystoolsPlugin


@pytest.fixture
def plugin():
    """Create plugin instance for testing."""
    return AgentupSystoolsPlugin()


@pytest.mark.asyncio
async def test_read_file(plugin):
    """Test the read_file capability."""
    # Create mock context
    context = CapabilityContext(
        request_id="test-123",
        user_id="test-user",
        agent_id="test-agent",
        conversation_id="test-conv",
        message="Test message",
        metadata={"parameters": {"input": "test input"}}
    )

    # Execute capability
    result = await plugin.read_file(context)

    # Verify result
    assert result is not None
    if isinstance(result, dict):
        assert "success" in result
        assert "content" in result
    else:
        assert isinstance(result, str)