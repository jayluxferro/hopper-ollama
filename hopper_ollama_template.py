#!/usr/bin/env python3
"""
HopperOllama: In-Hopper script + MCP server for Ollama-powered binary analysis.

- In Hopper: run explain_current_procedure() or summarize_current_procedure() to get
  LLM analysis in the log window.
- MCP: run launch_server() then connect Cursor/other clients to the HTTP MCP endpoint
  to use tools like analyze_procedure and ask_about_address.
"""

import json
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
from typing import Annotated, Iterator, Optional

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
_OLLAMA_CONTEXT_MAX_CHARS = int(os.environ.get("OLLAMA_CONTEXT_MAX_CHARS", "8192"))
_SCRIPT_VERSION = "1.0.0"
_VALID_ANALYSIS_TYPES = ("explain", "summarize", "suggest_name", "pattern", "vulnerability", "signature")


def _validate_analysis_type(analysis_type: str) -> None:
    """Raise ValueError if analysis_type is not in _VALID_ANALYSIS_TYPES."""
    if analysis_type not in _VALID_ANALYSIS_TYPES:
        raise ValueError(
            f"analysis_type must be one of {_VALID_ANALYSIS_TYPES!r}, got {analysis_type!r}"
        )


_SYSTEM_PROMPT = "You are a reverse-engineering assistant. You receive decompiled code or assembly from Hopper Disassembler. Answer concisely and in plain language. Do not repeat the code back."


_TRUNCATE_SEP = "\n... [truncated] ...\n"


def _truncate_for_context(text: str | None, max_chars: int) -> str | None:
    """Truncate text for Ollama context. When over limit, keep head + tail so the model sees entry and exit."""
    if not text:
        return text
    text = text.strip()
    if len(text) <= max_chars:
        return text
    if max_chars <= len(_TRUNCATE_SEP) + 2:
        return text[:max_chars] + "..."
    part = (max_chars - len(_TRUNCATE_SEP)) // 2
    return text[:part] + _TRUNCATE_SEP + text[-part:]

# Session override for model (set via set_ollama_model(); overrides env/default)
_current_model_override: str | None = None

# Context cache: (doc_name, entry_point, include_extra_context) -> context dict. Cleared on doc switch or document write.
_hopper_context_cache: dict[tuple[str, int, bool], dict] = {}


def _clear_context_cache() -> None:
    """Clear the get_hopper_context cache. Call when document is switched or modified."""
    global _hopper_context_cache
    _hopper_context_cache = {}


# Thread-local httpx client for Ollama (reuse connection; one client per thread)
_ollama_client_local: threading.local = threading.local()


def _get_ollama_client() -> httpx.Client:
    """Return a thread-local httpx client for Ollama (default timeout). Reused across requests in the same thread."""
    if not hasattr(_ollama_client_local, "client") or _ollama_client_local.client is None:
        _ollama_client_local.client = httpx.Client(timeout=_OLLAMA_TIMEOUT)
    return _ollama_client_local.client


def _ollama_retry_count() -> int:
    """Number of retries on transient failure (503, timeout). OLLAMA_RETRY_COUNT env, default 1."""
    if os.environ.get("OLLAMA_RETRY_COUNT") is None:
        return 1
    try:
        return max(0, int(os.environ["OLLAMA_RETRY_COUNT"]))
    except ValueError:
        return 1


def _ollama_retry_delay() -> float:
    """Seconds to wait before retry. OLLAMA_RETRY_DELAY env, default 1.0."""
    if os.environ.get("OLLAMA_RETRY_DELAY") is None:
        return 1.0
    try:
        return max(0.0, float(os.environ["OLLAMA_RETRY_DELAY"]))
    except ValueError:
        return 1.0


def _get_system_prompt() -> str:
    """System prompt: OLLAMA_SYSTEM_PROMPT env overrides default."""
    return os.environ.get("OLLAMA_SYSTEM_PROMPT") or _SYSTEM_PROMPT


def _ollama_generate(
    prompt: str,
    system: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    num_predict: int | None = None,
) -> str:
    base_url = (os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE).rstrip("/")
    use_model = model or _current_model_override or os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL
    payload = {"model": use_model, "prompt": prompt, "stream": False}
    if system is not None:
        payload["system"] = system
    else:
        payload["system"] = _get_system_prompt()
    if temperature is not None:
        payload["options"] = payload.get("options") or {}
        payload["options"]["temperature"] = temperature
    if top_p is not None:
        payload["options"] = payload.get("options") or {}
        payload["options"]["top_p"] = top_p
    if num_predict is not None:
        payload["options"] = payload.get("options") or {}
        payload["options"]["num_predict"] = num_predict
    # Env fallbacks for temperature/top_p/num_predict if not passed
    if "options" not in payload:
        opts = {}
        if os.environ.get("OLLAMA_TEMPERATURE") is not None:
            try:
                opts["temperature"] = float(os.environ["OLLAMA_TEMPERATURE"])
            except ValueError:
                pass
        if os.environ.get("OLLAMA_TOP_P") is not None:
            try:
                opts["top_p"] = float(os.environ["OLLAMA_TOP_P"])
            except ValueError:
                pass
        if os.environ.get("OLLAMA_NUM_PREDICT") is not None:
            try:
                opts["num_predict"] = int(os.environ["OLLAMA_NUM_PREDICT"])
            except ValueError:
                pass
        if opts:
            payload["options"] = opts
    elif os.environ.get("OLLAMA_NUM_PREDICT") is not None and (num_predict is None or "num_predict" not in payload.get("options", {})):
        payload["options"] = payload.get("options") or {}
        try:
            payload["options"]["num_predict"] = int(os.environ["OLLAMA_NUM_PREDICT"])
        except ValueError:
            pass
    last_err = None
    max_attempts = 1 + _ollama_retry_count()
    delay = _ollama_retry_delay()
    for attempt in range(max_attempts):
        try:
            client = _get_ollama_client()
            r = client.post(f"{base_url}/api/generate", json=payload)
            r.raise_for_status()
            return (r.json().get("response") or "").strip()
        except httpx.ConnectError as e:
            raise RuntimeError("Cannot connect to Ollama. Is it running? Start with: ollama serve")
        except httpx.HTTPStatusError as e:
            last_err = e
            if attempt < max_attempts - 1 and e.response.status_code in (503, 502, 429):
                time.sleep(delay)
                continue
            raise RuntimeError(f"Ollama API error: {e.response.status_code} {e.response.text}")
        except httpx.TimeoutException as e:
            last_err = e
            if attempt < max_attempts - 1:
                time.sleep(delay)
                continue
            raise RuntimeError(f"Ollama request timed out after {_OLLAMA_TIMEOUT}s")
    if last_err:
        raise RuntimeError(str(last_err))
    raise RuntimeError("Ollama request failed")


def _ollama_generate_stream(
    prompt: str,
    system: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    num_predict: int | None = None,
) -> Iterator[str]:
    """Stream Ollama generate response token by token. Yields chunks (response field from each NDJSON line). No retry."""
    base_url = (os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE).rstrip("/")
    use_model = model or _current_model_override or os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL
    payload = {"model": use_model, "prompt": prompt, "stream": True}
    if system is not None:
        payload["system"] = system
    else:
        payload["system"] = _get_system_prompt()
    if temperature is not None:
        payload["options"] = payload.get("options") or {}
        payload["options"]["temperature"] = temperature
    if top_p is not None:
        payload["options"] = payload.get("options") or {}
        payload["options"]["top_p"] = top_p
    if num_predict is not None:
        payload["options"] = payload.get("options") or {}
        payload["options"]["num_predict"] = num_predict
    if "options" not in payload:
        opts = {}
        if os.environ.get("OLLAMA_TEMPERATURE") is not None:
            try:
                opts["temperature"] = float(os.environ["OLLAMA_TEMPERATURE"])
            except ValueError:
                pass
        if os.environ.get("OLLAMA_TOP_P") is not None:
            try:
                opts["top_p"] = float(os.environ["OLLAMA_TOP_P"])
            except ValueError:
                pass
        if os.environ.get("OLLAMA_NUM_PREDICT") is not None:
            try:
                opts["num_predict"] = int(os.environ["OLLAMA_NUM_PREDICT"])
            except ValueError:
                pass
        if opts:
            payload["options"] = opts
    elif os.environ.get("OLLAMA_NUM_PREDICT") is not None:
        payload["options"] = payload.get("options") or {}
        try:
            payload["options"]["num_predict"] = int(os.environ["OLLAMA_NUM_PREDICT"])
        except ValueError:
            pass
    client = _get_ollama_client()
    with client.stream("POST", f"{base_url}/api/generate", json=payload) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    chunk = data.get("response", "")
                    if chunk:
                        yield chunk
                except json.JSONDecodeError:
                    pass


def _ollama_list_models() -> list[dict]:
    """Return list of installed models from GET /api/tags."""
    base_url = (os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE).rstrip("/")
    try:
        r = _get_ollama_client().get(f"{base_url}/api/tags", timeout=10)
        r.raise_for_status()
        data = r.json()
        return data.get("models") or []
    except Exception:
        return []


def _ollama_reachable() -> bool:
    """Return True if Ollama is reachable."""
    base_url = (os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE).rstrip("/")
    try:
        r = _get_ollama_client().get(f"{base_url}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


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
    elif analysis_type == "vulnerability":
        question = "List potential bugs or security issues (buffer overflows, missing checks, dangerous patterns). Be concise."
    elif analysis_type == "signature":
        question = "Suggest a C-like function signature or type summary (return type and main arguments) for this code. One line."
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


def get_hopper_context(address_or_name: str, include_extra_context: bool = False) -> dict:
    """Build context dict for the procedure at the given address or name.
    If include_extra_context is True, adds callers, callees, and referenced strings.
    Results are cached per (document, entry, include_extra_context); cache is cleared on doc switch or document write.
    """
    address = _resolve_address_or_name(address_or_name)
    segment, procedure = _get_segment_and_procedure(address)
    entry = procedure.getEntryPoint()
    cache_key = (doc.getDocumentName(), entry, include_extra_context)
    if cache_key in _hopper_context_cache:
        return _hopper_context_cache[cache_key]

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

    cap = _OLLAMA_CONTEXT_MAX_CHARS
    out = {
        "decompiled": _truncate_for_context(decompiled, cap) if decompiled else None,
        "assembly": _truncate_for_context(assembly, cap) if assembly else assembly,
        "procedure_name": name,
        "address": f"0x{entry:x}",
        "entry_point": entry,
        "segment": segment,
        "procedure": procedure,
    }
    if include_extra_context:
        callers = []
        callees = []
        try:
            for p in procedure.getAllCallerProcedures():
                ep = p.getEntryPoint()
                seg = p.getSegment()
                callers.append(seg.getNameAtAddress(ep) or f"0x{ep:x}")
            for ref in procedure.getAllCallees():
                callees.append(f"0x{ref.toAddress():x}")
        except Exception:
            pass
        out["callers"] = callers[:20]
        out["callees"] = callees[:30]
        refs_from = set()
        try:
            for bb in range(procedure.getBasicBlockCount()):
                block = procedure.getBasicBlock(bb)
                if not block:
                    continue
                addr = block.getStartingAddress()
                end = block.getEndingAddress()
                while addr < end:
                    refs = segment.getReferencesFromAddress(addr)
                    if refs:
                        for r in refs:
                            refs_from.add(r)
                    instr = segment.getInstructionAtAddress(addr)
                    addr += instr.getInstructionLength() if instr else 1
        except Exception:
            pass
        strings_near = []
        try:
            for ref_addr in list(refs_from)[:30]:
                for i in range(segment.getStringCount()):
                    saddr = segment.getStringAddressAtIndex(i)
                    if saddr is not None and abs(saddr - ref_addr) < 0x1000:
                        s = segment.getStringAtIndex(i)
                        if s and len(s) < 200:
                            strings_near.append(f"0x{saddr:x}: {repr(s)[:80]}")
        except Exception:
            pass
        out["referenced_strings"] = strings_near[:15]
    _hopper_context_cache[cache_key] = out
    return out


def _run_analysis(
    context: dict,
    analysis_type: str,
    custom_question: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    num_predict: int | None = None,
) -> str:
    prompt = _build_analysis_prompt(
        context.get("decompiled"),
        context.get("assembly"),
        context.get("procedure_name"),
        context["address"],
        analysis_type,
        custom_question,
    )
    if context.get("callers") or context.get("callees") or context.get("referenced_strings"):
        extra = []
        if context.get("callers"):
            extra.append("Callers: " + ", ".join(context["callers"][:10]))
        if context.get("callees"):
            extra.append("Callees (addresses): " + ", ".join(context["callees"][:15]))
        if context.get("referenced_strings"):
            extra.append("Referenced strings:\n" + "\n".join(context["referenced_strings"][:10]))
        prompt = prompt.rstrip() + "\n\nContext:\n" + "\n".join(extra)
    return _ollama_generate(
        prompt,
        system=_get_system_prompt(),
        model=model,
        temperature=temperature,
        top_p=top_p,
        num_predict=num_predict,
    )


def _run_analysis_stream(
    context: dict,
    analysis_type: str,
    custom_question: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    num_predict: int | None = None,
) -> Iterator[str]:
    """Stream Ollama analysis token by token. Yields response chunks. Only use for analysis_type 'explain' for best UX."""
    prompt = _build_analysis_prompt(
        context.get("decompiled"),
        context.get("assembly"),
        context.get("procedure_name"),
        context["address"],
        analysis_type,
        custom_question,
    )
    if context.get("callers") or context.get("callees") or context.get("referenced_strings"):
        extra = []
        if context.get("callers"):
            extra.append("Callers: " + ", ".join(context["callers"][:10]))
        if context.get("callees"):
            extra.append("Callees (addresses): " + ", ".join(context["callees"][:15]))
        if context.get("referenced_strings"):
            extra.append("Referenced strings:\n" + "\n".join(context["referenced_strings"][:10]))
        prompt = prompt.rstrip() + "\n\nContext:\n" + "\n".join(extra)
    yield from _ollama_generate_stream(
        prompt,
        system=_get_system_prompt(),
        model=model,
        temperature=temperature,
        top_p=top_p,
        num_predict=num_predict,
    )


def _get_selection_text():
    """Get the currently selected lines in the document (disassembly/decompiler view).
    Returns (text, start_addr, end_addr) or (None, None, None) if no selection.
    Uses Document.getSelectionAddressRange() and getRawSelectedLines() when available."""
    try:
        range_list = doc.getSelectionAddressRange()
        if not range_list or len(range_list) < 2:
            return None, None, None
        start_addr, end_addr = range_list[0], range_list[1]
        lines = doc.getRawSelectedLines()
        if not lines:
            return None, None, None
        text = "\n".join(lines).strip()
        if not text:
            return None, None, None
        return text, start_addr, end_addr
    except Exception:
        return None, None, None


def _run_analysis_for_selection(analysis_type: str) -> str:
    """Run analysis on the current selection; if no selection, run on current procedure."""
    global doc
    doc = Document.getCurrentDocument()
    text, start_addr, end_addr = _get_selection_text()
    if text is not None and start_addr is not None and end_addr is not None:
        context = {
            "decompiled": None,
            "assembly": text,
            "procedure_name": "Selected range",
            "address": f"0x{start_addr:x}–0x{end_addr:x}",
        }
        return _run_analysis(context, analysis_type)
    # No selection: fall back to current procedure
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    return _run_analysis(context, analysis_type)


# ---------------------------------------------------------------------------
# In-Hopper: run from script menu or Python prompt; result goes to Hopper log
# ---------------------------------------------------------------------------

def explain_current_procedure(stream: bool = False):
    """Get the current cursor address, run Ollama 'explain', and log the result in Hopper.
    If stream=True, log output as it arrives (token-by-token)."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    if stream:
        doc.log("[HopperOllama] ")
        buffer = ""
        for chunk in _run_analysis_stream(context, "explain"):
            buffer += chunk
            if "\n" in buffer or len(buffer) >= 80:
                doc.log(buffer)
                buffer = ""
        if buffer:
            doc.log(buffer)
        doc.log("\n")
    else:
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
# In-Hopper: analyze current selection (select blocks/lines, then run)
# ---------------------------------------------------------------------------
# Right-click is not scriptable; select a range in the disassembly or decompiler
# view, then run one of these from the Python prompt (or bind to a shortcut if Hopper supports it).

def explain_selection():
    """Analyze the currently selected lines with Ollama (explain). Select blocks in the disassembly or decompiler view, then run this. If nothing is selected, analyzes the current procedure."""
    global doc
    doc = Document.getCurrentDocument()
    result = _run_analysis_for_selection("explain")
    doc.log(f"[HopperOllama]\n{result}")


def summarize_selection():
    """Analyze the currently selected lines with Ollama (summarize). Select blocks, then run this. If no selection, uses current procedure."""
    global doc
    doc = Document.getCurrentDocument()
    result = _run_analysis_for_selection("summarize")
    doc.log(f"[HopperOllama]\n{result}")


def suggest_name_selection():
    """Suggest a name for the selected code. Select blocks, then run this. If no selection, uses current procedure."""
    global doc
    doc = Document.getCurrentDocument()
    result = _run_analysis_for_selection("suggest_name")
    doc.log(f"[HopperOllama] Suggested name: {result}")


def pattern_selection():
    """Describe the pattern/role of the selected code. Select blocks, then run this. If no selection, uses current procedure."""
    global doc
    doc = Document.getCurrentDocument()
    result = _run_analysis_for_selection("pattern")
    doc.log(f"[HopperOllama]\n{result}")


# ---------------------------------------------------------------------------
# In-Hopper: Ollama config and model switching
# ---------------------------------------------------------------------------

def list_ollama_models():
    """List installed Ollama models; output to Hopper log."""
    global doc
    doc = Document.getCurrentDocument()
    models = _ollama_list_models()
    if not models:
        doc.log("[HopperOllama] No models listed (Ollama unreachable or no models installed).")
        return
    lines = ["[HopperOllama] Installed models:"]
    for m in models:
        name = m.get("name") or m.get("model") or "?"
        size = m.get("size")
        lines.append(f"  {name}" + (f"  ({size})" if size else ""))
    doc.log("\n".join(lines))


def ollama_status():
    """Log current Ollama config and reachability (model, host, timeout, reachable)."""
    global doc
    doc = Document.getCurrentDocument()
    base = os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE
    model = _current_model_override or os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL
    reachable = _ollama_reachable()
    doc.log(f"[HopperOllama] Host: {base}\nModel: {model}\nReachable: {reachable}\nTimeout: {_OLLAMA_TIMEOUT}s")


def set_ollama_model(model_name: str):
    """Switch to a different Ollama model for this session. Pass the model name (e.g. llama3.1:8b). Use empty string to clear override."""
    global _current_model_override
    _current_model_override = model_name.strip() or None


def get_ollama_model() -> str:
    """Return the model currently used (session override, or env, or default)."""
    return _current_model_override or os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL


# ---------------------------------------------------------------------------
# In-Hopper: apply name, write comment, vulnerability, signature
# ---------------------------------------------------------------------------

def suggest_and_apply_name_current_procedure():
    """Suggest a name for the current procedure; prompt to apply (or edit) and set the label in Hopper."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    name = _run_analysis(context, "suggest_name").strip()
    if not name:
        doc.log("[HopperOllama] No name suggested.")
        return
    try:
        reply = Document.ask(f"Apply this name? (edit or leave empty to cancel)\n{name}")
    except Exception:
        doc.log("[HopperOllama] Apply cancelled (Document.ask not available).")
        return
    if reply is None or not str(reply).strip():
        doc.log("[HopperOllama] Cancelled.")
        return
    name = str(reply).strip()
    entry = context.get("entry_point") or addr
    seg = context.get("segment")
    if seg and seg.setNameAtAddress(entry, name):
        doc.saveDocument()
        doc.log(f"[HopperOllama] Set name at 0x{entry:x} to: {name}")
    else:
        doc.log("[HopperOllama] Failed to set name.")


def explain_and_comment_current_procedure():
    """Run explain on the current procedure and set the result as a comment at the procedure entry."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    result = _run_analysis(context, "explain")
    entry = context.get("entry_point", addr)
    seg = context.get("segment")
    comment = (result[:2000] + "...") if len(result) > 2000 else result
    if seg and doc:
        try:
            seg.setCommentAtAddress(entry, comment)
            doc.saveDocument()
            doc.log(f"[HopperOllama] Comment set at 0x{entry:x}")
        except Exception as e:
            doc.log(f"[HopperOllama] Failed to set comment: {e}")


def clear_comment_current_procedure():
    """Clear the prefix comment at the current procedure's entry point. Does not call Ollama."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    entry = context.get("entry_point", addr)
    seg = context.get("segment")
    if seg and doc:
        try:
            seg.setCommentAtAddress(entry, "")
            doc.saveDocument()
            doc.log(f"[HopperOllama] Comment cleared at 0x{entry:x}")
        except Exception as e:
            doc.log(f"[HopperOllama] Failed to clear comment: {e}")


def vulnerability_current_procedure():
    """Run vulnerability/security analysis on the current procedure and log the result."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}", include_extra_context=True)
    result = _run_analysis(context, "vulnerability")
    doc.log(f"[HopperOllama]\n{result}")


def vulnerability_selection():
    """Run vulnerability analysis on the current selection (or current procedure if no selection)."""
    global doc
    doc = Document.getCurrentDocument()
    result = _run_analysis_for_selection("vulnerability")
    doc.log(f"[HopperOllama]\n{result}")


def signature_current_procedure():
    """Suggest a C-like signature for the current procedure and log the result."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    context = get_hopper_context(f"0x{addr:x}")
    result = _run_analysis(context, "signature")
    doc.log(f"[HopperOllama] Signature: {result}")


def signature_selection():
    """Suggest a C-like signature for the selected code (or current procedure if no selection)."""
    global doc
    doc = Document.getCurrentDocument()
    result = _run_analysis_for_selection("signature")
    doc.log(f"[HopperOllama] Signature: {result}")


# ---------------------------------------------------------------------------
# In-Hopper: batch summarize procedures in selection
# ---------------------------------------------------------------------------

def summarize_procedures_in_selection():
    """Summarize each procedure in the current selection (or current procedure only). Results to log."""
    global doc
    doc = Document.getCurrentDocument()
    text, start_addr, end_addr = _get_selection_text()
    if start_addr is None or end_addr is None:
        addr = doc.getCurrentAddress()
        context = get_hopper_context(f"0x{addr:x}")
        result = _run_analysis(context, "summarize")
        doc.log(f"[HopperOllama]\n{result}")
        return
    segment = doc.getSegmentAtAddress(start_addr)
    if not segment:
        doc.log("[HopperOllama] No segment at selection.")
        return
    seen = set()
    results = []
    addr = start_addr
    while addr < end_addr:
        proc = segment.getProcedureAtAddress(addr)
        if proc:
            entry = proc.getEntryPoint()
            if entry not in seen:
                seen.add(entry)
                name = segment.getNameAtAddress(entry) or f"0x{entry:x}"
                ctx = get_hopper_context(f"0x{entry:x}")
                summary = _run_analysis(ctx, "summarize")
                results.append(f"{name}: {summary.strip()}")
            block = proc.getBasicBlockAtAddress(addr)
            addr = block.getEndingAddress() if block else addr + 4
        else:
            addr += 4
    doc.log("[HopperOllama] Summaries:\n" + "\n\n".join(results) if results else "[HopperOllama] No procedures in selection.")


def explain_procedures_in_selection():
    """Explain each procedure in the current selection (or current procedure only). Results to log."""
    global doc
    doc = Document.getCurrentDocument()
    text, start_addr, end_addr = _get_selection_text()
    if start_addr is None or end_addr is None:
        addr = doc.getCurrentAddress()
        context = get_hopper_context(f"0x{addr:x}")
        result = _run_analysis(context, "explain")
        doc.log(f"[HopperOllama]\n{result}")
        return
    segment = doc.getSegmentAtAddress(start_addr)
    if not segment:
        doc.log("[HopperOllama] No segment at selection.")
        return
    seen = set()
    results = []
    addr = start_addr
    while addr < end_addr:
        proc = segment.getProcedureAtAddress(addr)
        if proc:
            entry = proc.getEntryPoint()
            if entry not in seen:
                seen.add(entry)
                name = segment.getNameAtAddress(entry) or f"0x{entry:x}"
                ctx = get_hopper_context(f"0x{entry:x}")
                explanation = _run_analysis(ctx, "explain")
                results.append(f"--- {name} ---\n{explanation.strip()}")
            block = proc.getBasicBlockAtAddress(addr)
            addr = block.getEndingAddress() if block else addr + 4
        else:
            addr += 4
    doc.log("[HopperOllama] Explanations:\n" + "\n\n".join(results) if results else "[HopperOllama] No procedures in selection.")


def _procedures_in_selection_batch(analysis_type: str) -> tuple[list[str], str]:
    """Run analysis_type on each procedure in selection (or current). Returns (list of '--- name ---\\nresult', log_title)."""
    global doc
    doc = Document.getCurrentDocument()
    text, start_addr, end_addr = _get_selection_text()
    if start_addr is None or end_addr is None:
        addr = doc.getCurrentAddress()
        context = get_hopper_context(f"0x{addr:x}")
        result = _run_analysis(context, analysis_type)
        label = context.get("procedure_name") or context["address"]
        return ([f"--- {label} ---\n{result.strip()}"], analysis_type)
    segment = doc.getSegmentAtAddress(start_addr)
    if not segment:
        return ([], analysis_type)
    seen = set()
    results = []
    addr = start_addr
    while addr < end_addr:
        proc = segment.getProcedureAtAddress(addr)
        if proc:
            entry = proc.getEntryPoint()
            if entry not in seen:
                seen.add(entry)
                name = segment.getNameAtAddress(entry) or f"0x{entry:x}"
                ctx = get_hopper_context(f"0x{entry:x}")
                out = _run_analysis(ctx, analysis_type)
                results.append(f"--- {name} ---\n{out.strip()}")
            block = proc.getBasicBlockAtAddress(addr)
            addr = block.getEndingAddress() if block else addr + 4
        else:
            addr += 4
    return (results, analysis_type)


def vulnerability_procedures_in_selection():
    """Run vulnerability analysis on each procedure in the current selection (or current procedure only). Results to log."""
    global doc
    doc = Document.getCurrentDocument()
    results, _ = _procedures_in_selection_batch("vulnerability")
    doc.log("[HopperOllama] Vulnerability:\n" + "\n\n".join(results) if results else "[HopperOllama] No procedures in selection.")


def signature_procedures_in_selection():
    """Suggest C-like signatures for each procedure in the current selection (or current procedure only). Results to log."""
    global doc
    doc = Document.getCurrentDocument()
    results, _ = _procedures_in_selection_batch("signature")
    doc.log("[HopperOllama] Signatures:\n" + "\n\n".join(results) if results else "[HopperOllama] No procedures in selection.")


def pattern_procedures_in_selection():
    """Run pattern analysis on each procedure in the current selection (or current procedure only). Results to log."""
    global doc
    doc = Document.getCurrentDocument()
    results, _ = _procedures_in_selection_batch("pattern")
    doc.log("[HopperOllama] Patterns:\n" + "\n\n".join(results) if results else "[HopperOllama] No procedures in selection.")


def suggest_name_procedures_in_selection():
    """Suggest names for each procedure in the current selection (or current procedure only). Results to log."""
    global doc
    doc = Document.getCurrentDocument()
    results, _ = _procedures_in_selection_batch("suggest_name")
    doc.log("[HopperOllama] Suggested names:\n" + "\n\n".join(results) if results else "[HopperOllama] No procedures in selection.")


# ---------------------------------------------------------------------------
# In-Hopper: RE navigation helpers (log segments, procedures, xrefs)
# ---------------------------------------------------------------------------

def log_segments():
    """List all segments (name, start, length) in the current document and log to the Hopper log."""
    global doc
    doc = Document.getCurrentDocument()
    lines = ["[HopperOllama] Segments:"]
    try:
        count = doc.getSegmentCount()
        for i in range(count):
            seg = doc.getSegment(i)
            if seg:
                start = seg.getStartingAddress()
                length = seg.getLength()
                lines.append(f"  {i}: {seg.getName()}  0x{start:x} len={length}")
    except Exception as e:
        lines.append(f"  Error: {e}")
    doc.log("\n".join(lines))


def log_procedures_in_current_segment(limit: int = 100):
    """List procedures in the current segment (cursor position) and log address and name. Optional limit (default 100)."""
    global doc
    doc = Document.getCurrentDocument()
    seg = None
    try:
        seg = doc.getCurrentSegment()
    except Exception:
        pass
    if not seg:
        doc.log("[HopperOllama] No current segment (move cursor into a segment).")
        return
    lines = [f"[HopperOllama] Procedures in {seg.getName()}:"]
    try:
        count = min(seg.getProcedureCount(), limit)
        for i in range(count):
            proc = seg.getProcedureAtIndex(i)
            if proc:
                entry = proc.getEntryPoint()
                name = seg.getNameAtAddress(entry)
                lines.append(f"  0x{entry:x}  {name or f'sub_{entry:x}'}")
    except Exception as e:
        lines.append(f"  Error: {e}")
    doc.log("\n".join(lines))


def log_xrefs_to_current_address():
    """List addresses that reference the current cursor address (xrefs to) and log them."""
    global doc
    doc = Document.getCurrentDocument()
    addr = doc.getCurrentAddress()
    segment = doc.getSegmentAtAddress(addr)
    if not segment:
        doc.log(f"[HopperOllama] No segment at 0x{addr:x}.")
        return
    lines = [f"[HopperOllama] Xrefs to 0x{addr:x}:"]
    try:
        from_addrs = segment.getReferencesOfAddress(addr)
        if from_addrs:
            for from_addr in from_addrs[:200]:
                lines.append(f"  from 0x{from_addr:x}")
        else:
            lines.append("  (none)")
    except Exception as e:
        lines.append(f"  Error: {e}")
    doc.log("\n".join(lines))


def export_report_to_file(path: str | None = None, analysis_type: str = "summarize"):
    """Run analysis on procedures in the current selection (or current procedure), write a markdown report to a file.
    If path is None, prompts for path (default: hopper_analysis_report.md in current directory).
    analysis_type: one of explain, summarize, suggest_name, pattern, vulnerability, signature (default: summarize)."""
    if analysis_type not in _VALID_ANALYSIS_TYPES:
        analysis_type = "summarize"
    global doc
    doc = Document.getCurrentDocument()
    if path is None:
        default_path = os.path.join(os.getcwd(), "hopper_analysis_report.md")
        try:
            reply = Document.ask(f"Report path (default: {default_path}):", default_path) if getattr(Document, "ask", None) else None
        except Exception:
            reply = None
        path = (reply or "").strip() or default_path
    text, start_addr, end_addr = _get_selection_text()
    if start_addr is None or end_addr is None:
        addr = doc.getCurrentAddress()
        context = get_hopper_context(f"0x{addr:x}")
        result = _run_analysis(context, analysis_type)
        report = f"# Hopper analysis report ({analysis_type})\n\n--- {context.get('procedure_name') or context['address']} ---\n{result}"
    else:
        segment = doc.getSegmentAtAddress(start_addr)
        if not segment:
            doc.log("[HopperOllama] No segment at selection.")
            return
        seen = set()
        results = []
        addr = start_addr
        while addr < end_addr:
            proc = segment.getProcedureAtAddress(addr)
            if proc:
                entry = proc.getEntryPoint()
                if entry not in seen:
                    seen.add(entry)
                    name = segment.getNameAtAddress(entry) or f"0x{entry:x}"
                    ctx = get_hopper_context(f"0x{entry:x}")
                    out = _run_analysis(ctx, analysis_type)
                    results.append(f"--- {name} ---\n{out.strip()}")
                block = proc.getBasicBlockAtAddress(addr)
                addr = block.getEndingAddress() if block else addr + 4
            else:
                addr += 4
        report = f"# Hopper analysis report ({analysis_type})\n\n" + "\n\n".join(results) if results else "# No procedures in selection.\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)
    doc.log(f"[HopperOllama] Report written to {path}")


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


@mcp.tool
def list_ollama_models() -> dict:
    """List installed Ollama models (names and optional size). Use before set_ollama_model to switch model."""
    models = _ollama_list_models()
    return {
        "reachable": _ollama_reachable(),
        "models": [{"name": m.get("name") or m.get("model"), "size": m.get("size")} for m in models],
    }


@mcp.tool
def get_ollama_config() -> dict:
    """Return current Ollama config: model, host, timeout, context_max_chars, num_predict (from env), reachable. Useful to show the user or debug."""
    num_predict = None
    if os.environ.get("OLLAMA_NUM_PREDICT") is not None:
        try:
            num_predict = int(os.environ["OLLAMA_NUM_PREDICT"])
        except ValueError:
            pass
    return {
        "version": _SCRIPT_VERSION,
        "model": _current_model_override or os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL,
        "host": os.environ.get("OLLAMA_HOST") or _OLLAMA_BASE,
        "timeout": _OLLAMA_TIMEOUT,
        "context_max_chars": _OLLAMA_CONTEXT_MAX_CHARS,
        "num_predict": num_predict,
        "retry_count": _ollama_retry_count(),
        "retry_delay": _ollama_retry_delay(),
        "reachable": _ollama_reachable(),
    }


@mcp.tool
def set_ollama_model(model_name: Annotated[str, "Model name (e.g. llama3.1:8b). Use list_ollama_models to see installed models."]) -> str:
    """Switch to a different Ollama model for this session. Pass empty string to clear override and use default/env."""
    global _current_model_override
    _current_model_override = model_name.strip() or None
    current = _current_model_override or os.environ.get("OLLAMA_MODEL") or _OLLAMA_MODEL
    return f"Model set to: {current}"


@mcp.tool
def get_procedure_context(
    address_or_name: Annotated[str, "Procedure address (e.g. 0x1000) or symbol name"],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
    include_extra_context: Annotated[bool, Field(description="If True, include callers, callees, and referenced strings.")] = False,
) -> dict:
    """Get decompiled code and assembly for a procedure without calling Ollama. Returns procedure_name, address, decompiled, assembly; optionally callers, callees, referenced_strings. Use to display code or send elsewhere."""
    _ensure_document(doc_id)
    context = get_hopper_context(address_or_name, include_extra_context=include_extra_context)
    out = {
        "procedure_name": context.get("procedure_name"),
        "address": context["address"],
        "decompiled": context.get("decompiled"),
        "assembly": context.get("assembly"),
    }
    if include_extra_context:
        for key in ("callers", "callees", "referenced_strings"):
            if key in context:
                out[key] = context[key]
    return out


@mcp.tool
def get_address_range_context(
    start_address_hex: Annotated[str, "Start of range (e.g. 0x1000)"],
    end_address_hex: Annotated[str, "End of range (e.g. 0x1100)"],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
) -> dict:
    """Get assembly (and metadata) for an address range without calling Ollama. Returns procedure_name (Address range), address (range string), decompiled (None), assembly. Use to display code or send elsewhere."""
    _ensure_document(doc_id)
    start_addr = _parse_hex(start_address_hex)
    end_addr = _parse_hex(end_address_hex)
    if start_addr >= end_addr:
        raise ValueError("start_address must be less than end_address")
    context = _get_context_for_address_range(start_addr, end_addr)
    return {
        "procedure_name": context.get("procedure_name"),
        "address": context["address"],
        "decompiled": context.get("decompiled"),
        "assembly": context.get("assembly"),
    }


@mcp.tool
def list_segments(
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
) -> dict:
    """List all segments in the document (name, start address, length). Useful for RE overview and to pick a segment for list_procedures_in_segment."""
    _ensure_document(doc_id)
    segments = []
    try:
        count = doc.getSegmentCount()
        for i in range(count):
            seg = doc.getSegment(i)
            if seg:
                start = seg.getStartingAddress()
                length = seg.getLength()
                segments.append({
                    "segment_index": i,
                    "name": seg.getName(),
                    "start_address": f"0x{start:x}",
                    "length": length,
                    "end_address": f"0x{start + length:x}",
                })
    except Exception:
        pass
    return {"segments": segments, "total": len(segments)}


@mcp.tool
def list_procedures_in_segment(
    segment_identifier: Annotated[str, "Segment index (e.g. '0') or segment name (e.g. '__text')"],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
    limit: Annotated[int, Field(description="Max number of procedures to return (default 500).")] = 500,
) -> dict:
    """List procedures in a segment: entry address and name for each. Use after list_segments to batch-analyze or explore a segment."""
    _ensure_document(doc_id)
    seg = None
    try:
        if segment_identifier.strip().isdigit():
            idx = int(segment_identifier.strip())
            seg = doc.getSegment(idx)
        else:
            seg = doc.getSegmentByName(segment_identifier.strip())
    except Exception:
        pass
    if not seg:
        raise ValueError(f"Segment not found: {segment_identifier!r}. Use list_segments to see valid indices and names.")
    procedures = []
    try:
        count = min(seg.getProcedureCount(), limit)
        for i in range(count):
            proc = seg.getProcedureAtIndex(i)
            if proc:
                entry = proc.getEntryPoint()
                name = seg.getNameAtAddress(entry)
                procedures.append({
                    "address": f"0x{entry:x}",
                    "name": name or f"sub_{entry:x}",
                })
    except Exception:
        pass
    return {"procedures": procedures, "segment": seg.getName(), "total": len(procedures)}


@mcp.tool
def get_xrefs_to(
    address_hex: Annotated[str, "Address to find references to (e.g. 0x1000)"],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
) -> dict:
    """List addresses that reference the given address (cross-references / xrefs to). Useful to see who calls a function or references data."""
    _ensure_document(doc_id)
    addr = _parse_hex(address_hex)
    segment = doc.getSegmentAtAddress(addr)
    if not segment:
        raise ValueError(f"No segment at {address_hex}")
    refs = []
    try:
        from_addrs = segment.getReferencesOfAddress(addr)
        if from_addrs:
            for from_addr in from_addrs[:200]:
                refs.append({"from_address": f"0x{from_addr:x}"})
    except Exception:
        pass
    return {"target_address": address_hex, "xrefs": refs, "count": len(refs)}


@mcp.tool
def list_strings(
    segment_identifier: Annotated[str, "Segment index (e.g. '0') or segment name (e.g. '__cstring')"],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
    filter_substring: Annotated[Optional[str], Field(description="Optional. Only include strings containing this substring (case-sensitive).")] = None,
    limit: Annotated[int, Field(description="Max number of strings to return (default 500).")] = 500,
) -> dict:
    """List strings in a segment (address and value). Optional filter_substring to search. Useful for RE (find URLs, keys, etc.)."""
    _ensure_document(doc_id)
    seg = None
    try:
        if segment_identifier.strip().isdigit():
            idx = int(segment_identifier.strip())
            seg = doc.getSegment(idx)
        else:
            seg = doc.getSegmentByName(segment_identifier.strip())
    except Exception:
        pass
    if not seg:
        raise ValueError(f"Segment not found: {segment_identifier!r}. Use list_segments to see valid indices and names.")
    strings = []
    try:
        count = seg.getStringCount()
        for i in range(count):
            if len(strings) >= limit:
                break
            saddr = seg.getStringAddressAtIndex(i)
            s = seg.getStringAtIndex(i)
            if s is None:
                continue
            s = str(s).strip()
            if filter_substring and filter_substring not in s:
                continue
            strings.append({"address": f"0x{saddr:x}", "value": s[:500]})
    except Exception:
        pass
    return {"strings": strings, "segment": seg.getName(), "total": len(strings)}


@mcp.tool
def set_comment_at_address(
    address_hex: Annotated[str, "Address (e.g. 0x1000)"],
    comment: Annotated[str, "Comment text to set at this address (prefix comment)."],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID.")] = None,
) -> str:
    """Set a prefix comment at the given address in Hopper. Does not call Ollama. Saves the document."""
    _ensure_document(doc_id)
    addr = _parse_hex(address_hex)
    segment = doc.getSegmentAtAddress(addr)
    if not segment:
        raise ValueError(f"No segment at {address_hex}")
    if segment.setCommentAtAddress(addr, comment):
        doc.saveDocument()
        _clear_context_cache()
        return f"Comment set at {address_hex}"
    return f"Failed to set comment at {address_hex}"


@mcp.tool
def clear_comment_at_address(
    address_hex: Annotated[str, "Address (e.g. 0x1000)"],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID.")] = None,
) -> str:
    """Clear the prefix comment at the given address in Hopper. Does not call Ollama. Saves the document."""
    return set_comment_at_address(address_hex, "", doc_id)


@mcp.tool
def rename_procedure(
    address_or_name: Annotated[str, "Procedure address (e.g. 0x1000) or symbol name"],
    new_name: Annotated[str, "New label name to set at the procedure entry."],
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID.")] = None,
) -> str:
    """Set the label/name at the procedure's entry point. Does not call Ollama. Use for scripting or after applying a suggested name. Saves the document."""
    _ensure_document(doc_id)
    addr = _resolve_address_or_name(address_or_name)
    segment, procedure = _get_segment_and_procedure(addr)
    entry = procedure.getEntryPoint()
    if segment.setNameAtAddress(entry, new_name):
        doc.saveDocument()
        _clear_context_cache()
        return f"Renamed procedure at 0x{entry:x} to: {new_name}"
    return f"Failed to rename at 0x{entry:x}"


def _ensure_document(doc_id: Optional[int]) -> None:
    """If doc_id is set, switch global doc to that document."""
    if doc_id is None:
        return
    global doc
    all_docs = Document.getAllDocuments()
    if doc_id < 0 or doc_id >= len(all_docs):
        raise ValueError(f"Invalid doc_id {doc_id}. Valid range: 0 to {len(all_docs) - 1}")
    doc = all_docs[doc_id]
    _clear_context_cache()


def _get_context_for_address_range(start_addr: int, end_addr: int) -> dict:
    """Build context dict for an address range (assembly only; no decompilation)."""
    segment = doc.getSegmentAtAddress(start_addr)
    if not segment:
        raise ValueError(f"No segment at 0x{start_addr:x}")
    assembly_lines = []
    addr = start_addr
    max_instructions = 200
    while addr < end_addr and len(assembly_lines) < max_instructions:
        instr = segment.getInstructionAtAddress(addr)
        if instr:
            assembly_lines.append(f"  0x{addr:x}: {instr.getInstructionString()}")
            addr += instr.getInstructionLength()
        else:
            addr += 1
    assembly = "\n".join(assembly_lines) if assembly_lines else ""
    assembly = assembly or "(no instructions in range)"
    return {
        "decompiled": None,
        "assembly": _truncate_for_context(assembly, _OLLAMA_CONTEXT_MAX_CHARS) or assembly,
        "procedure_name": "Address range",
        "address": f"0x{start_addr:x}–0x{end_addr:x}",
    }


@mcp.tool
def analyze_procedure(
    address_or_name: Annotated[str, "Procedure address (e.g. 0x1000) or symbol name"],
    analysis_type: Annotated[
        str,
        "One of: explain, summarize, suggest_name, pattern, vulnerability, signature",
    ] = "explain",
    doc_id: Annotated[
        Optional[int],
        Field(description="Optional. Document ID to analyze (from get_all_documents). If omitted, uses current document."),
    ] = None,
    model: Annotated[Optional[str], Field(description="Optional. Override model for this call (e.g. llama3.1:8b).")] = None,
    temperature: Annotated[Optional[float], Field(description="Optional. Override temperature for this call.")] = None,
    top_p: Annotated[Optional[float], Field(description="Optional. Override top_p for this call.")] = None,
    set_comment: Annotated[bool, Field(description="If True and analysis_type is explain, set the result as a comment at the procedure.")] = False,
    apply_suggested_name: Annotated[bool, Field(description="If True and analysis_type is suggest_name, apply the suggested name in Hopper.")] = False,
    include_extra_context: Annotated[bool, Field(description="If True, include callers, callees, and referenced strings in context.")] = False,
    num_predict: Annotated[Optional[int], Field(description="Optional. Max tokens to generate (OLLAMA_NUM_PREDICT env or this param).")] = None,
) -> str:
    """Run Ollama analysis on a procedure. Types: explain, summarize, suggest_name, pattern, vulnerability, signature.
    Optional: model, temperature, top_p, num_predict; set_comment (for explain); apply_suggested_name (for suggest_name); include_extra_context."""
    _validate_analysis_type(analysis_type)
    _ensure_document(doc_id)
    context = get_hopper_context(address_or_name, include_extra_context=include_extra_context)
    result = _run_analysis(
        context, analysis_type, model=model, temperature=temperature, top_p=top_p, num_predict=num_predict
    )
    if set_comment and analysis_type == "explain" and result:
        entry = context.get("entry_point")
        seg = context.get("segment")
        comment = (result[:2000] + "...") if len(result) > 2000 else result
        if entry is not None and seg:
            try:
                seg.setCommentAtAddress(entry, comment)
                doc.saveDocument()
            except Exception:
                pass
    if apply_suggested_name and analysis_type == "suggest_name" and result:
        name = result.strip()
        entry = context.get("entry_point")
        seg = context.get("segment")
        if name and entry is not None and seg and seg.setNameAtAddress(entry, name):
            doc.saveDocument()
            result = f"Applied name '{name}' at 0x{entry:x}. " + result
    return result


@mcp.tool
def analyze_address_range(
    start_address_hex: Annotated[str, "Start of range (e.g. 0x1000)"],
    end_address_hex: Annotated[str, "End of range (e.g. 0x1100)"],
    analysis_type: Annotated[
        str,
        "One of: explain, summarize, suggest_name, pattern, vulnerability, signature",
    ] = "explain",
    doc_id: Annotated[
        Optional[int],
        Field(description="Optional. Document ID (from get_all_documents). If omitted, uses current document."),
    ] = None,
    model: Annotated[Optional[str], Field(description="Optional. Override model for this call.")] = None,
    temperature: Annotated[Optional[float], None] = None,
    top_p: Annotated[Optional[float], None] = None,
    num_predict: Annotated[Optional[int], Field(description="Optional. Max tokens to generate.")] = None,
) -> str:
    """Run Ollama analysis on an address range (e.g. selected blocks). Analysis uses the assembly in that range."""
    _validate_analysis_type(analysis_type)
    _ensure_document(doc_id)
    start_addr = _parse_hex(start_address_hex)
    end_addr = _parse_hex(end_address_hex)
    if start_addr >= end_addr:
        raise ValueError("start_address must be less than end_address")
    context = _get_context_for_address_range(start_addr, end_addr)
    return _run_analysis(context, analysis_type, model=model, temperature=temperature, top_p=top_p, num_predict=num_predict)


@mcp.tool
def analyze_procedures(
    address_or_name_list: Annotated[list[str], "List of procedure addresses or symbol names"],
    analysis_type: Annotated[str, "One of: explain, summarize, suggest_name, pattern, vulnerability, signature"] = "summarize",
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID.")] = None,
    model: Annotated[Optional[str], None] = None,
    num_predict: Annotated[Optional[int], Field(description="Optional. Max tokens per procedure.")] = None,
    delay_seconds: Annotated[Optional[float], Field(description="Optional. Seconds to wait between each procedure call (rate limiting).")] = None,
) -> str:
    """Run Ollama analysis on multiple procedures. Returns combined result (one summary per procedure for summarize)."""
    _validate_analysis_type(analysis_type)
    _ensure_document(doc_id)
    results = []
    for i, addr_or_name in enumerate(address_or_name_list[:20]):
        if delay_seconds and i > 0:
            time.sleep(delay_seconds)
        try:
            context = get_hopper_context(addr_or_name)
            out = _run_analysis(context, analysis_type, model=model, num_predict=num_predict)
            label = context.get("procedure_name") or context["address"]
            results.append(f"--- {label} ---\n{out}")
        except Exception as e:
            results.append(f"--- {addr_or_name} ---\nError: {e}")
    return "\n\n".join(results)


@mcp.tool
def export_analysis_report(
    address_or_name_list: Annotated[list[str], "List of procedure addresses or symbol names to include in the report"],
    analysis_type: Annotated[str, "One of: explain, summarize, suggest_name, pattern, vulnerability, signature"] = "summarize",
    output_path: Annotated[
        Optional[str],
        Field(description="Optional. File path to write markdown report. If omitted, returns the report text."),
    ] = None,
    doc_id: Annotated[Optional[int], Field(description="Optional. Document ID (from get_all_documents).")] = None,
    model: Annotated[Optional[str], None] = None,
    delay_seconds: Annotated[Optional[float], Field(description="Optional. Seconds between procedure calls.")] = None,
) -> str:
    """Run analysis on each procedure and produce a markdown report. Optionally write to output_path, otherwise return report text."""
    _validate_analysis_type(analysis_type)
    _ensure_document(doc_id)
    body = analyze_procedures(
        address_or_name_list,
        analysis_type=analysis_type,
        doc_id=doc_id,
        model=model,
        delay_seconds=delay_seconds,
    )
    title = f"# Hopper analysis report ({analysis_type})\n\n"
    report = title + body
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        return f"Report written to {output_path}"
    return report


@mcp.tool
def ask_about_address(
    address_or_name: Annotated[str, "Address (e.g. 0x1000) or symbol name"],
    question: Annotated[str, "Your question about this procedure (e.g. 'What does this function return?')"],
    doc_id: Annotated[
        Optional[int],
        Field(description="Optional. Document ID (from get_all_documents). If omitted, uses current document."),
    ] = None,
    model: Annotated[Optional[str], None] = None,
    temperature: Annotated[Optional[float], None] = None,
    top_p: Annotated[Optional[float], None] = None,
    num_predict: Annotated[Optional[int], Field(description="Optional. Max tokens to generate.")] = None,
    include_extra_context: Annotated[bool, None] = False,
) -> str:
    """Ask a free-form question about the procedure at the given address. Uses Ollama."""
    _ensure_document(doc_id)
    context = get_hopper_context(address_or_name, include_extra_context=include_extra_context)
    return _run_analysis(
        context, "explain", custom_question=question,
        model=model, temperature=temperature, top_p=top_p, num_predict=num_predict,
    )


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
    return _ollama_generate(prompt, system=_get_system_prompt())


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
    print("  Procedure: explain | summarize | suggest_name | pattern | vulnerability | signature (current_procedure / _selection)")
    print("  Apply/comment: suggest_and_apply_name_current_procedure()  |  explain_and_comment_current_procedure()  |  clear_comment_current_procedure()")
    print("  Batch: summarize_procedures_in_selection()  |  explain_procedures_in_selection()  |  vulnerability_procedures_in_selection()  |  signature_procedures_in_selection()  |  pattern_procedures_in_selection()  |  suggest_name_procedures_in_selection()")
    print("  RE helpers: log_segments()  |  log_procedures_in_current_segment(limit?)  |  log_xrefs_to_current_address()")
    print("  Ollama: list_ollama_models()  |  ollama_status()  |  set_ollama_model(name)  |  get_ollama_model()")
    print("  MCP: launch_server_ollama()  →  http://localhost:42070/mcp/")
    print("  Both: run HopperPyMCP script first, then launch_both_servers()  →  42069 + 42070")
