# HopperOllama

Ollama-powered analysis for [Hopper Disassembler](https://www.hopperapp.com/): use a local LLM to explain, summarize, or name procedures directly from Hopper, and expose the same analysis via MCP for Cursor and other clients.

## Features

- **In-Hopper script**: Run from Hopper’s Python prompt (results in the log):
  - `explain_current_procedure()`, `summarize_current_procedure()`, `suggest_name_current_procedure()`, `pattern_current_procedure()`
- **MCP server**: Run `launch_server_ollama()` in Hopper, then connect Cursor to get tools (the console blocks while the server runs):
  - `analyze_procedure(address_or_name, analysis_type)` — `explain` | `summarize` | `suggest_name` | `pattern`
  - `ask_about_address(address_or_name, question)` — free-form question about a procedure
  - `compare_procedures(address_or_name_1, address_or_name_2)` — compare two procedures

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

Options: `--force` to overwrite an existing script, `--dry-run` to only print actions.

This installs **hopper_ollama.py** into Hopper’s Scripts directory and ensures dependencies (fastmcp, httpx) are available to Hopper’s Python.

## Usage

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
   The server runs and blocks the Hopper Python console until it stops. Use a second Hopper window if you need the console for analysis while MCP is running.
2. Add HopperOllama to Cursor’s MCP config (e.g. `~/.cursor/mcp.json` or `.cursor/mcp.json`):

   ```json
   {
     "mcpServers": {
       "hopper-ollama": {
         "url": "http://localhost:42070/mcp"
       }
     }
   }
   ```

3. Reload Cursor. Use the tools **analyze_procedure**, **ask_about_address**, and **compare_procedures** in chat.

**Note:** Hopper must stay open with the server running for MCP clients to connect. Port **42070**.

## Configuration

- **Ollama model**: Set `OLLAMA_MODEL` (e.g. `llama3.1:8b`, `codellama`) or rely on the default `llama3.1:8b`.
- **Ollama host**: Set `OLLAMA_HOST` if Ollama is not on `http://localhost:11434` (e.g. `http://192.168.1.10:11434`).

## Project layout

```
HopperOllama/
├── pyproject.toml
├── hopper_ollama/           # Package (installed via uv sync)
│   ├── __init__.py
│   ├── ollama_client.py     # Ollama HTTP client
│   └── prompts.py           # Prompt templates
├── hopper_ollama_template.py  # Script template (paths substituted by install.py)
├── install.py
└── README.md
```

## License

MIT (or same as your preference).
