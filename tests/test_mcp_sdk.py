import pytest

pytest.importorskip("mcp")

from mcp import Client

from scamshield.mcp_server import mcp


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_tools_are_exposed_through_official_sdk():
    async with Client(mcp, raise_exceptions=True) as client:
        tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}

        assert names == {
            "analyze_message",
            "check_url_reputation",
            "get_safety_guidance",
        }


@pytest.mark.anyio
async def test_official_sdk_can_call_analyze_message():
    async with Client(mcp, raise_exceptions=True) as client:
        result = await client.call_tool(
            "analyze_message",
            {"message": "Pay a processing fee today at https://example.com."},
        )

        assert result.structured_content["ok"] is True
        assert result.structured_content["result"]["status"] == "suspicious"
