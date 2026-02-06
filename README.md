# HopperOllama

Ollama-powered analysis for [Hopper Disassembler](https://www.hopperapp.com/): use a local LLM to explain, summarize, or name procedures directly from Hopper, and expose the same analysis via MCP for Cursor and other clients.

## Features

- **In-Hopper script** (run from Hopper’s Python prompt; results in the log):
  - **Procedure / selection:** `explain_*`, `summarize_*`, `suggest_name_*`, `pattern_*`, `vulnerability_*`, `signature_*` (suffix `_current_procedure` or `_selection`; selection uses the current procedure if nothing is selected). Use `explain_current_procedure(stream=True)` to stream the explanation to the log as it arrives.
  - **Apply / annotate:** `suggest_and_apply_name_current_procedure()` (prompt to apply or edit the name), `explain_and_comment_current_procedure()` (write explanation as a comment), `clear_comment_current_procedure()` (clear comment at current procedure).
  - **Batch:** `summarize_procedures_in_selection()`, `explain_procedures_in_selection()`, `vulnerability_procedures_in_selection()`, `signature_procedures_in_selection()`, `pattern_procedures_in_selection()`, `suggest_name_procedures_in_selection()` — run that analysis on each procedure in the selected range.
  - **Report:** `export_report_to_file(path?, analysis_type?)` — run analysis on procedures in selection (or current) and write markdown; `analysis_type` is one of `explain`, `summarize`, `suggest_name`, `pattern`, `vulnerability`, `signature` (default summarize); prompts for path if omitted.
  - **Ollama:** `list_ollama_models()`, `ollama_status()`, `set_ollama_model(name)`, `get_ollama_model()`.
- **MCP server** (run `launch_server_ollama()` in Hopper; console blocks while the server runs):
  - **Documents:** `get_all_documents()`, `get_current_document()`, `set_current_document(doc_id)`.
  - **Context (no LLM):** `get_procedure_context(...)`, `get_address_range_context(...)`. **RE navigation:** `list_segments(doc_id?)`; `list_procedures_in_segment(segment_index_or_name, doc_id?, limit?)`; `get_xrefs_to(address_hex, doc_id?)`; `list_strings(segment_index_or_name, doc_id?, filter_substring?, limit?)` — strings in a segment with optional search. Export/import listing is not available in the Hopper Python API. `set_comment_at_address(...)`, `clear_comment_at_address(...)`, `rename_procedure(...)`.
  - **In-Hopper RE helpers:** `log_segments()` — log segment list; `log_procedures_in_current_segment(limit?)` — log procedures in the segment at cursor; `log_xrefs_to_current_address()` — log xrefs to cursor address.
  - **Analysis:** `analyze_procedure(address_or_name, analysis_type, doc_id?, model?, temperature?, top_p?, num_predict?, set_comment?, apply_suggested_name?, include_extra_context?)` — types: `explain`, `summarize`, `suggest_name`, `pattern`, `vulnerability`, `signature`.
  - **Range / batch:** `analyze_address_range(start_hex, end_hex, ...)`, `analyze_procedures([...], analysis_type, doc_id?, model?, num_predict?, delay_seconds?)`, `export_analysis_report([...], analysis_type?, output_path?, doc_id?, model?, delay_seconds?)`.
  - **Other:** `ask_about_address(..., model?, temperature?, top_p?, num_predict?, include_extra_context?)`, `compare_procedures(...)`.
  - **Ollama:** `list_ollama_models()`, `get_ollama_config()` (includes version, model, host, retry, etc.), `set_ollama_model(model_name)`.

## Requirements

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** (recommended) or pip
- **Hopper Disassembler** (v4 or v5)
- **[Ollama](https://ollama.com/)** installed and running (`ollama serve`), with at least one model (e.g. `ollama pull llama3.1:8b`)

## Installation

```bash
cd HopperOllama
uv run install.py
```

Options: `--force` to overwrite an existing script, `--dry-run` to only print actions, `--dev` to generate the script in the project directory for symlink-based development (see Development).

This installs **hopper_ollama.py** into Hopper’s Scripts directory and ensures dependencies (fastmcp, httpx) are available to Hopper’s Python.

## Usage

**Note:** Scripts are only available after you load a binary into Hopper (Scripts stay disabled until a document is open).

### 1. In Hopper (no MCP)

1. Open a binary in Hopper and move the cursor to a procedure (or an address inside it).
2. Run the **hopper_ollama** script from Hopper’s Scripts (or paste its contents into the Python prompt).
3. In the Python prompt, run one of:
   - **By cursor or selection:** `explain_*`, `summarize_*`, `suggest_name_*`, `pattern_*`, `vulnerability_*`, `signature_*` (use `_current_procedure` or `_selection`; e.g. `explain_selection()`).
   - **Apply name / write comment:** `suggest_and_apply_name_current_procedure()`, `explain_and_comment_current_procedure()`.
   - **Batch:** Select a range, then e.g. `summarize_procedures_in_selection()`, `explain_procedures_in_selection()`, `vulnerability_procedures_in_selection()`, `signature_procedures_in_selection()`, `pattern_procedures_in_selection()`, `suggest_name_procedures_in_selection()`.
   - **Report:** `export_report_to_file()` (prompts for path) or `export_report_to_file("/path/to/report.md", "vulnerability")`; `analysis_type` can be any of explain, summarize, suggest_name, pattern, vulnerability, signature.
   - **RE navigation:** `log_segments()`, `log_procedures_in_current_segment(100)`, `log_xrefs_to_current_address()`.
   - **Model:** `list_ollama_models()`, `ollama_status()`, `set_ollama_model("llama3.1:8b")`, `get_ollama_model()`.

Output appears in Hopper’s log window.

### 2. MCP (e.g. Cursor)

1. In Hopper: run the **hopper_ollama** script, then in the Python prompt run:
   ```python
   launch_server_ollama()
   ```
   The server runs and blocks the Hopper Python console until it stops. 2. Add HopperOllama to Cursor’s MCP config (e.g. `~/.cursor/mcp.json` or `.cursor/mcp.json`):

   ```json
   {
     "mcpServers": {
       "hopper-ollama": {
         "url": "http://localhost:42070/mcp"
       }
     }
   }
   ```

3. Reload Cursor. Use the tools in chat.

**Note:** Hopper must stay open with the server running for MCP clients to connect. Port **42070**.

### Running both HopperPyMCP and HopperOllama

To run **both** MCP servers in the same Hopper session (one binary loaded):

1. Run the **HopperPyMCP** script first (Scripts → run the PyMCP script).
2. Run the **HopperOllama** script (Scripts → run the Ollama script).
3. In the Python prompt, call:
   ```python
   launch_both_servers()
   ```
   Both servers start (PyMCP on 42069, Ollama on 42070) and the console blocks until they stop. Add both URLs to Cursor's MCP config to use them together.

### Multiple documents

When you have **more than one binary open** in the same Hopper session, analysis uses the "current" document. To target a specific one:

1. Call **get_all_documents()** to list open documents (each has a `doc_id` and `document_name`).
2. Call **set_current_document(doc_id)** with the `doc_id` of the document to analyze (or pass `doc_id` into the analysis tools).

You can ask in chat: “Which document should I analyze?” — the AI can call `get_all_documents()`, show you the list, then call `set_current_document(doc_id)` or use the optional `doc_id` parameter once you pick (by name or number).

## Configuration

- **Ollama model**: Set `OLLAMA_MODEL` (e.g. `llama3.1:8b`) or use `set_ollama_model(name)` in-Hopper / MCP for the session.
- **Ollama host**: Set `OLLAMA_HOST` if Ollama is not on `http://localhost:11434`.
- **Optional:** `OLLAMA_TEMPERATURE`, `OLLAMA_TOP_P` (generation); `OLLAMA_NUM_PREDICT` (max tokens to generate); `OLLAMA_SYSTEM_PROMPT` (overrides the default reverse-engineering system prompt); `OLLAMA_CONTEXT_MAX_CHARS` (default 8192 — truncate decompiled/assembly sent to the model; when over limit, head and tail are kept so the model sees entry and exit); `OLLAMA_RETRY_COUNT` (retries on 503/timeout, default 1); `OLLAMA_RETRY_DELAY` (seconds before retry, default 1.0). Ollama HTTP client is reused per thread for connection reuse. Procedure context is cached per (document, entry); cache is cleared when switching document or when setting/clearing comments or renaming procedures. MCP analysis tools validate `analysis_type` and raise a clear error if invalid.

## Uninstallation

```bash
uv run uninstall.py
```

Use `--dry-run` to see what would be removed, or `--confirm` to skip the confirmation prompt.

## Troubleshooting

- **"Cannot connect to Ollama"** — Start Ollama first: `ollama serve`. Ensure no firewall is blocking port 11434.
- **Model not found** — Pull the model: `ollama pull llama3.1:8b` (or the model you set in `OLLAMA_MODEL`).
- **Procedure/address not found** — Confirm the address or symbol exists in the **current** document (use `set_current_document(doc_id)` or the `doc_id` parameter if you have multiple documents open).

## Development

### Development installation
Generate the script in the project directory and symlink it into Hopper for edit-and-test without re-installing:

```bash
uv run install.py --dev
# Then symlink (macOS example; Linux: ~/GNUstep/Library/ApplicationSupport/Hopper/Scripts/)
ln -s "$(pwd)/hopper_ollama.py" ~/Library/Application\ Support/Hopper/Scripts/
```

Edit `hopper_ollama_template.py` (and the `hopper_ollama` package as needed); the symlinked script in Hopper will pick up changes on next run. Re-run `uv run install.py --dev` only if you need to refresh path placeholders in the generated script.

### Running tests

```bash
uv run pytest tests/ -v
```

Tests use a mock Document and patch Ollama so no Hopper or Ollama process is required.

## Project layout

```
HopperOllama/
├── LICENSE
├── pyproject.toml
├── hopper_ollama/             # Package (installed via uv sync)
│   ├── __init__.py
│   ├── ollama_client.py       # Ollama HTTP client
│   └── prompts.py            # Prompt templates
├── hopper_ollama_template.py  # Script template (paths substituted by install.py)
├── install.py
├── uninstall.py
├── tests/
│   ├── __init__.py
│   ├── mock_hopper_ollama.py  # Mock Document for tests
│   └── test_hopper_ollama.py
└── README.md
```

## License

MIT. See [LICENSE](LICENSE).
