"""
Tests for HopperOllama MCP tools using FastMCP Client (in-memory).
Mocks Document via tests.mock_hopper_ollama and patches get_hopper_context / _ollama_generate so no Hopper or Ollama is required.
"""

import os
import sys
import pytest
from unittest.mock import patch

# Ensure project root is on path and mock Document is used when template imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hopper_ollama_template as server
from fastmcp import Client


@pytest.fixture(autouse=True)
def reset_document():
    """Reset mock current document before each test."""
    from tests.mock_hopper_ollama import Document
    Document.set_current_for_tests(0)


@pytest.mark.asyncio
async def test_get_all_documents():
    """List open documents returns doc_id and names."""
    async with Client(server.mcp) as client:
        result = await client.call_tool("get_all_documents", {})
    data = result.data
    assert "total_documents" in data
    assert data["total_documents"] == 2
    assert "documents" in data
    assert len(data["documents"]) == 2
    assert data["documents"][0]["doc_id"] == 0
    assert data["documents"][0]["document_name"] == "main_binary"
    assert data["documents"][1]["document_name"] == "other_binary"


@pytest.mark.asyncio
async def test_get_current_document():
    """Current document returns doc_id and name."""
    async with Client(server.mcp) as client:
        result = await client.call_tool("get_current_document", {})
    data = result.data
    assert data["doc_id"] == 0
    assert data["document_name"] == "main_binary"


@pytest.mark.asyncio
async def test_set_current_document():
    """set_current_document switches the document used for analysis."""
    async with Client(server.mcp) as client:
        result = await client.call_tool("set_current_document", {"doc_id": 1})
        assert "other_binary" in result.data
        result2 = await client.call_tool("get_current_document", {})
    assert result2.data["doc_id"] == 1
    assert result2.data["document_name"] == "other_binary"


@pytest.mark.asyncio
async def test_set_current_document_invalid():
    """Invalid doc_id raises."""
    async with Client(server.mcp) as client:
        with pytest.raises(Exception) as exc_info:
            await client.call_tool("set_current_document", {"doc_id": 99})
    assert "Invalid doc_id" in str(exc_info.value)


@pytest.mark.asyncio
async def test_analyze_procedure_with_mocked_ollama():
    """analyze_procedure returns Ollama output (mocked)."""
    mock_context = {
        "decompiled": "int main() { return 0; }",
        "assembly": None,
        "procedure_name": "main",
        "address": "0x1000",
    }
    with patch.object(server, "get_hopper_context", return_value=mock_context), \
         patch.object(server, "_ollama_generate", return_value="Mocked explanation."):
        async with Client(server.mcp) as client:
            result = await client.call_tool("analyze_procedure", {"address_or_name": "0x1000", "analysis_type": "explain"})
    assert "Mocked explanation" in result.data


@pytest.mark.asyncio
async def test_analyze_procedure_with_doc_id():
    """analyze_procedure accepts optional doc_id."""
    mock_context = {"decompiled": "code", "assembly": None, "procedure_name": "fn", "address": "0x2000"}
    with patch.object(server, "get_hopper_context", return_value=mock_context), \
         patch.object(server, "_ollama_generate", return_value="OK"):
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "analyze_procedure",
                {"address_or_name": "0x2000", "analysis_type": "summarize", "doc_id": 1},
            )
    assert "OK" in result.data


@pytest.mark.asyncio
async def test_ask_about_address():
    """ask_about_address returns mocked answer."""
    mock_context = {"decompiled": "code", "assembly": None, "procedure_name": "fn", "address": "0x1000"}
    with patch.object(server, "get_hopper_context", return_value=mock_context), \
         patch.object(server, "_ollama_generate", return_value="Mocked answer."):
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "ask_about_address",
                {"address_or_name": "0x1000", "question": "What does this return?"},
            )
    assert "Mocked answer" in result.data


@pytest.mark.asyncio
async def test_compare_procedures():
    """compare_procedures returns mocked comparison."""
    def mock_get_hopper_context(addr):
        base = {"decompiled": "code", "assembly": None, "procedure_name": "fn", "address": addr}
        return base
    with patch.object(server, "get_hopper_context", side_effect=mock_get_hopper_context), \
         patch.object(server, "_ollama_generate", return_value="Mocked comparison."):
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "compare_procedures",
                {"address_or_name_1": "0x1000", "address_or_name_2": "0x2000"},
            )
    assert "Mocked comparison" in result.data


@pytest.mark.asyncio
async def test_analyze_procedure_invalid_doc_id():
    """analyze_procedure with invalid doc_id raises."""
    with patch.object(server, "get_hopper_context") as mock_ctx:
        mock_ctx.return_value = {"decompiled": "x", "assembly": None, "procedure_name": "f", "address": "0x1"}
        async with Client(server.mcp) as client:
            with pytest.raises(Exception) as exc_info:
                await client.call_tool(
                    "analyze_procedure",
                    {"address_or_name": "0x1000", "analysis_type": "explain", "doc_id": 99},
                )
    assert "Invalid doc_id" in str(exc_info.value)


@pytest.mark.asyncio
async def test_list_strings():
    """list_strings returns strings from segment (mocked segment has 3 strings)."""
    async with Client(server.mcp) as client:
        result = await client.call_tool("list_strings", {"segment_identifier": "0"})
    data = result.data
    assert data["segment"] == "__cstring"
    assert data["total"] == 3
    assert len(data["strings"]) == 3
    addrs = [s["address"] for s in data["strings"]]
    vals = [s["value"] for s in data["strings"]]
    assert "0x2000" in addrs and "0x2008" in addrs and "0x2010" in addrs
    assert "hello" in vals and "world" in vals and "https://example.com" in vals


@pytest.mark.asyncio
async def test_list_strings_filter():
    """list_strings with filter_substring returns only matching strings."""
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "list_strings",
            {"segment_identifier": "0", "filter_substring": "example"},
        )
    data = result.data
    assert data["total"] == 1
    assert data["strings"][0]["value"] == "https://example.com"
