#!/usr/bin/env python3
"""
HopperOllama: In-Hopper script + MCP server for Ollama-powered binary analysis.

- In Hopper: run explain_current_procedure() or summarize_current_procedure() to get
  LLM analysis in the log window.
- MCP: run launch_server() then connect Cursor/other clients to the HTTP MCP endpoint
  to use tools like analyze_procedure and ask_about_address.
"""

import sys
import os
import time

# Path injection for Hopper plugin (do not add imports before this block)
if "python" not in sys.executable:
    sys.path.insert(0, "{{PYTHON_LIB_DYNLOAD}}")
    sys.path.insert(0, "{{PYTHON_LIB_PATH}}")
    sys.path.insert(0, "{{PYTHON_SITE_PACKAGES}}")

# Hopper's stdout has no isatty(); uvicorn/FastMCP need it for logging config
def _isatty_false():
    return False
sys.stdout.isatty = _isatty_false

# When run from Python (e.g. tests), use mock Document if available
if "python" in sys.executable:
    try:
        from tests.mock_hopper_ollama import Document
    except ImportError:
        pass

import threading
from typing import Annotated, Optional

import httpx
from pydantic import Field
from fastmcp import FastMCP

# Hopper injects Document when the script runs inside Hopper
doc = Document.getCurrentDocument()

mcp = FastMCP(name="HopperOllama")

# Capture for launch_both_servers() so run_server_ollama always uses this script's doc/mcp
_ollama_doc = doc
_ollama_mcp = mcp

# ---------------------------------------------------------------------------
# Inlined: Ollama client + prompts (no hopper_ollama package import)
# ---------------------------------------------------------------------------

_OLLAMA_BASE = "http://localhost:11434"
_OLLAMA_MODEL = "llama3.1:8b"
_OLLAMA_TIMEOUT = 120.0
_SYSTEM_PROMPT = "You are a reverse-engineering assistant. You receive decompiled code or assembly from Hopper Disassembler. Answer concisely and in plain language. Do not repeat the code back."


def _ollama_generate(prompt: str, system: str | None = None) -> str:
    base_url = (os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE).rstrip("/")
    model = os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL
    payload = {"model": model, "prompt": prompt, "stream": False}
    if system:
        payload["system"] = system
    try:
        with httpx.Client(timeout=_OLLAMA_TIMEOUT) as client:
            r = client.post(f"{base_url}/api/generate", json=payload)
            r.raise_for_status()
            return (r.json().get("response") or "").strip()
    except httpx.ConnectError:
        raise RuntimeError("Cannot connect to Ollama. Is it running? Start with: ollama serve")
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ollama API error: {e.response.status_code} {e.response.text}")
    except httpx.TimeoutException:
        raise RuntimeError(f"Ollama request timed out after {_OLLAMA_TIMEOUT}s")


def _build_analysis_prompt(decompiled, assembly, procedure_name, address, analysis_type, custom_question=None):
    code_block = decompiled or assembly or "(no code available)"
    label = procedure_name or address
    if custom_question:
        question = custom_question.strip()
    elif analysis_type == "explain":
        question = "Explain what this function does and how it works."
    elif analysis_type == "summarize":
        question = "Summarize this function in one or two sentences."
    elif analysis_type == "suggest_name":
        question = "Suggest a short, descriptive name for this function based on its behavior (e.g. parse_header, validate_input). Reply with only the name, no explanation."
    elif analysis_type == "pattern":
        question = "What pattern or role does this code implement? (e.g. getter, validation, parser, callback). One short sentence."
    else:
        question = "Analyze this function."
    return f"""Procedure at {address} ({label}):

```
{code_block}
```

{question}"""

# ---------------------------------------------------------------------------
# Helpers: address resolution and Hopper context (require doc, Document)
# ---------------------------------------------------------------------------

def _parse_hex(address_hex: str) -> int:
    try:
        return int(address_hex.strip().replace("0x", ""), 16)
    except ValueError:
        raise ValueError(f"Invalid hex address: '{address_hex}'")


def _resolve_address_or_name(address_or_name: str) -> int:
    s = address_or_name.strip()
    if s.lower().startswith("0x"):
        return _parse_hex(s)
    addr = doc.getAddressForName(s)
    if addr is None or addr == 0 or addr == 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"No address found for name '{s}'")
    return addr


def _get_segment_and_procedure(address: int):
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment at address 0x{address:x}")
    procedure = segment.getProcedureAtAddress(address)
    if not procedure:
        raise ValueError(f"No procedure at address 0x{address:x}")
    return segment, procedure


def _get_procedure_name(segment, address: int) -> str:
    name = segment.getNameAtAddress(address)
    if name:
        return name
    return f"0x{address:x}"


def get_hopper_context(address_or_name: str) -> dict:
    """Build context dict for the procedure at the given address or name.
    Used by both the in-Hopper commands and MCP tools.
    Uses global doc: in-Hopper callers set doc to getCurrentDocument() first; MCP uses doc set by set_current_document(doc_id).
    """
    address = _resolve_address_or_name(address_or_name)
    segment, procedure = _get_segment_and_procedure(address)
    entry = procedure.getEntryPoint()
    name = _get_procedure_name(segment, entry)

    decompiled = procedure.decompile()
    assembly_lines = []
    try:
        for bb in range(procedure.getBasicBlockCount()):
            block = procedure.getBasicBlock(bb)
            if not block:
                continue
            addr = block.getStartingAddress()
            end = block.getEndingAddress()
            count = 0
            while addr < end and count < 30:
                instr = segment.getInstructionAtAddress(addr)
                if instr:
                    assembly_lines.append(f"  0x{addr:x}: {instr.getInstructionString()}")
                    addr += instr.getInstructionLength()
                    count += 1
                else:
                    addr += 1
    except Exception:
        pass
    assembly = "\n".join(assembly_lines) if assembly_lines else None

    return {
        "decompiled": decompiled.strip() if decompiled else None,
        "assembly": assembly,
        "procedure_name": name,
        "address": f"0x{entry:x}",
    }


def _run_analysis(context: dict, analysis_type: str, custom_question: str | None = None) -> str:
    prompt = _build_analysis_prompt(
        context.get("decompiled"),
        context.get("assembly"),
        context.get("procedure_name"),
        context["address"],
        analysis_type,
        custom_question,
    )
    return _ollama_generate(prompt, system=_SYSTEM_PROMPT)


# ---------------------------------------------------------------------------
# In-Hopper: run from script menu or Python prompt; result goes to Hopper log
# ---------------------------------------------------------------------------

def explain_current_procedure():
    """Get the current cursor address, run Ollama 'explain', and log the result in Hopper."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    result = _run_analysis(context, "explain")
    doc.log(f"[HopperOllama]\n{result}")


def summarize_current_procedure():
    """Get the current cursor address, run Ollama 'summarize', and log the result in Hopper."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    result = _run_analysis(context, "summarize")
    doc.log(f"[HopperOllama]\n{result}")


def suggest_name_current_procedure():
    """Get the current cursor address, run Ollama 'suggest_name', and log the result in Hopper."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    result = _run_analysis(context, "suggest_name")
    doc.log(f"[HopperOllama] Suggested name: {result}")


def pattern_current_procedure():
    """Get the current cursor address, run Ollama 'pattern', and log the result in Hopper."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    result = _run_analysis(context, "pattern")
    doc.log(f"[HopperOllama]\n{result}")


# ---------------------------------------------------------------------------
# MCP tools (used when launch_server() is running and client calls the tool)
# ---------------------------------------------------------------------------
# Document selection: when you have multiple Hopper windows (e.g. one running
# Ollama, one with the main binary), call get_all_documents then set_current_document(doc_id)
# so analysis targets the right file. The AI can prompt the user to choose if needed.

@mcp.tool
def get_all_documents() -> dict:
    """List all open Hopper documents with doc_id and names.
    Use with set_current_document(doc_id) so analysis runs on the intended document
    (e.g. when the server runs in a different window than the one you are analyzing)."""
    all_docs = Document.getAllDocuments()
    return {
        "total_documents": len(all_docs),
        "documents": [
            {
                "doc_id": i,
                "document_name": d.getDocumentName(),
                "executable_path": d.getExecutableFilePath(),
                "entry_point": f"0x{d.getEntryPoint():x}",
                "segment_count": d.getSegmentCount(),
                "analysis_active": d.backgroundProcessActive(),
            }
            for i, d in enumerate(all_docs)
        ],
    }


@mcp.tool
def get_current_document() -> dict:
    """Return which document is currently used for analysis (doc_id and name).
    This is the document set at script load or by set_current_document(doc_id)."""
    all_docs = Document.getAllDocuments()
    doc_id = -1
    for i, d in enumerate(all_docs):
        if d == doc:
            doc_id = i
            break
    return {
        "doc_id": doc_id,
        "document_name": doc.getDocumentName(),
        "executable_path": doc.getExecutableFilePath(),
        "entry_point": f"0x{doc.getEntryPoint():x}",
        "segment_count": doc.getSegmentCount(),
        "analysis_active": doc.backgroundProcessActive(),
    }


@mcp.tool
def set_current_document(doc_id: Annotated[int, Field(description="Document ID from get_all_documents() or get_current_document()", ge=0)]) -> str:
    """Set which open document to analyze. Call this when you have multiple documents or windows
    so the user can pick the one to analyze (e.g. list from get_all_documents, then set_current_document(doc_id))."""
    global doc
    all_docs = Document.getAllDocuments()
    if doc_id < 0 or doc_id >= len(all_docs):
        raise ValueError(f"Invalid doc_id {doc_id}. Valid range: 0 to {len(all_docs) - 1}")
    doc = all_docs[doc_id]
    return f"Now analyzing doc_id {doc_id}: {doc.getDocumentName()}"


def _ensure_document(doc_id: Optional[int]) -> None:
    """If doc_id is set, switch global doc to that document."""
    if doc_id is None:
        return
    global doc
    all_docs = Document.getAllDocuments()
    if doc_id < 0 or doc_id >= len(all_docs):
        raise ValueError(f"Invalid doc_id {doc_id}. Valid range: 0 to {len(all_docs) - 1}")
    doc = all_docs[doc_id]


@mcp.tool
def analyze_procedure(
    address_or_name: Annotated[str, "Procedure address (e.g. 0x1000) or symbol name"],
    analysis_type: Annotated[
        str,
        "One of: explain, summarize, suggest_name, pattern",
    ] = "explain",
    doc_id: Annotated[
        Optional[int],
        Field(description="Optional. Document ID to analyze (from get_all_documents). If omitted, uses current document."),
    ] = None,
) -> str:
    """Run Ollama analysis on a procedure: explain, summarize, suggest a name, or describe its pattern.
    Pass doc_id to analyze a procedure in a specific document without calling set_current_document first."""
    _ensure_document(doc_id)
    context = get_hopper_context(address_or_name)
    return _run_analysis(context, analysis_type)


@mcp.tool
def ask_about_address(
    address_or_name: Annotated[str, "Address (e.g. 0x1000) or symbol name"],
    question: Annotated[str, "Your question about this procedure (e.g. 'What does this function return?')"],
    doc_id: Annotated[
        Optional[int],
        Field(description="Optional. Document ID (from get_all_documents). If omitted, uses current document."),
    ] = None,
) -> str:
    """Ask a free-form question about the procedure at the given address. Uses Ollama.
    Pass doc_id to ask about a procedure in a specific document."""
    _ensure_document(doc_id)
    context = get_hopper_context(address_or_name)
    return _run_analysis(context, "explain", custom_question=question)


@mcp.tool
def compare_procedures(
    address_or_name_1: Annotated[str, "First procedure: address (e.g. 0x1000) or symbol name"],
    address_or_name_2: Annotated[str, "Second procedure: address or symbol name"],
    doc_id: Annotated[
        Optional[int],
        Field(description="Optional. Document ID for both procedures (from get_all_documents). If omitted, uses current document."),
    ] = None,
) -> str:
    """Compare two procedures: describe similarities, differences, and relationship. Uses Ollama.
    Pass doc_id to compare procedures in a specific document."""
    _ensure_document(doc_id)
    ctx1 = get_hopper_context(address_or_name_1)
    ctx2 = get_hopper_context(address_or_name_2)
    code1 = ctx1.get("decompiled") or ctx1.get("assembly") or "(no code)"
    code2 = ctx2.get("decompiled") or ctx2.get("assembly") or "(no code)"
    label1 = ctx1.get("procedure_name") or ctx1["address"]
    label2 = ctx2.get("procedure_name") or ctx2["address"]
    prompt = f"""Procedure A at {ctx1['address']} ({label1}):

```
{code1}
```

Procedure B at {ctx2['address']} ({label2}):

```
{code2}
```

Compare these two functions: similarities, differences, and how they might relate (e.g. caller/callee, shared pattern, variants). Be concise."""
    return _ollama_generate(prompt, system=_SYSTEM_PROMPT)


# ---------------------------------------------------------------------------
# MCP server entrypoint
# ---------------------------------------------------------------------------

def run_server_ollama():
    import traceback
    # Uvicorn installs signal handlers that don't work in threads and can hang; disable them.
    try:
        import uvicorn
        uvicorn.Server.install_signal_handlers = lambda *_, **__: None
    except Exception:
        pass
    try:
        _ollama_doc.log("[HopperOllama] Server thread started, calling mcp.run()...")
        _ollama_mcp.run(transport="http", host="127.0.0.1", port=42070)
    except Exception as e:
        tb = traceback.format_exc()
        msg = f"[HopperOllama] Server failed: {e}\n{tb}"
        print(msg)  # always print so it's visible in console
        try:
            _ollama_doc.log(msg)
        except Exception:
            pass


def launch_server_ollama():
    """Start the HopperOllama MCP server on port 42070. Blocks the console until the server stops."""
    print("Starting HopperOllama server on port 42070...")
    server_thread = threading.Thread(target=run_server_ollama, daemon=False)
    server_thread.start()
    print("Server: http://localhost:42070/mcp/")
    server_thread.join()


# Backward compat: launch_server() starts this server when this script is the only one loaded
launch_server = launch_server_ollama


def launch_both_servers():
    """Start both HopperPyMCP (42069) and HopperOllama (42070) in the same session. Blocks until both stop.
    Requires the HopperPyMCP script to have been run first in this session (so run PyMCP script, then this script, then call launch_both_servers())."""
    try:
        pymcp_runner = run_server_pymcp
    except NameError:
        print("HopperPyMCP is not loaded. Run the HopperPyMCP script first, then run this script again.")
        print("Then call launch_both_servers() to start both servers.")
        return
    t_ollama = threading.Thread(target=run_server_ollama, daemon=False)
    t_pymcp = threading.Thread(target=pymcp_runner, daemon=False)
    # Start Ollama first so it binds to 42070 before PyMCP runs; short delay avoids startup race
    t_ollama.start()
    time.sleep(0.5)
    t_pymcp.start()
    print("Both servers started. Console will block until they stop.")
    print("  HopperPyMCP:  http://localhost:42069/mcp/")
    print("  HopperOllama: http://localhost:42070/mcp/")
    t_ollama.join()
    t_pymcp.join()


# ---------------------------------------------------------------------------
# Banner when script loads in Hopper
# ---------------------------------------------------------------------------

if "python" not in sys.executable:
    print("HopperOllama loaded.")
    print("  In-Hopper: explain_current_procedure()  |  summarize_current_procedure()  |  suggest_name_current_procedure()  |  pattern_current_procedure()")
    print("  MCP: launch_server_ollama()  →  http://localhost:42070/mcp/")
    print("  Both: run HopperPyMCP script first, then launch_both_servers()  →  42069 + 42070")
