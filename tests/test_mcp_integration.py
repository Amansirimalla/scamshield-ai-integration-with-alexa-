import pytest

from scamshield.mcp_client import ScamShieldMCPClient


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_real_mcp_client_server_workflow():
    pytest.importorskip("mcp")
    from scamshield.mcp_server import mcp

    client = ScamShieldMCPClient(server=mcp)
    result = await client.analyze_message("Your account will be blocked today at https://example.com.")

    assert result["status"] == "suspicious"
    assert result["findings"]


@pytest.mark.anyio
async def test_real_mcp_url_tool_returns_unknown_without_provider():
    pytest.importorskip("mcp")
    from scamshield.mcp_server import mcp

    client = ScamShieldMCPClient(server=mcp)
    result = await client.check_url_reputation("https://example.com")

    assert result["status"] in {"unknown", "no_threat_found", "malicious", "lookup_failed", "provider_error"}
