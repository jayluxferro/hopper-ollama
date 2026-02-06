# HopperOllama

Ollama-powered analysis for [Hopper Disassembler](https://www.hopperapp.com/): use a local LLM to explain, summarize, or name procedures directly from Hopper, and expose the same analysis via MCP for Cursor and other clients.

## Features

- **In-Hopper script**: Run from Hopper’s Python prompt (results in the log):
  - `explain_current_procedure()`, `summarize_current_procedure()`, `suggest_name_current_procedure()`, `pattern_current_procedure()`
- **MCP server**: Run `launch_server_ollama()` in Hopper, then connect Cursor to get tools (the console blocks while the server runs):
  - `get_all_documents()` — list open documents with `doc_id` and names
  - `get_current_document()` — which document is currently used for analysis
  - `set_current_document(doc_id)` — choose which document to analyze when you have multiple open
  - `analyze_procedure(address_or_name, analysis_type, doc_id?)` — `explain` | `summarize` | `suggest_name` | `pattern` (optional `doc_id` to target a document in one call)
  - `ask_about_address(address_or_name, question, doc_id?)` — free-form question about a procedure
  - `compare_procedures(address_or_name_1, address_or_name_2, doc_id?)` — compare two procedures

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
   - `explain_current_procedure()` — full explanation
   - `summarize_current_procedure()` — short summary
   - `suggest_name_current_procedure()` — suggested name
   - `pattern_current_procedure()` — pattern/role (e.g. getter, parser)

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

- **Ollama model**: Set `OLLAMA_MODEL` (e.g. `llama3.1:8b`, `codellama`) or rely on the default `llama3.1:8b`.
- **Ollama host**: Set `OLLAMA_HOST` if Ollama is not on `http://localhost:11434` (e.g. `http://192.168.1.10:11434`).

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
