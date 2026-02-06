"""Ollama HTTP client for generate/chat. No Hopper dependencies."""

import os
import httpx

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_TIMEOUT = 120.0


def ollama_generate(
    prompt: str,
    *,
    model: str | None = None,
    system: str | None = None,
    base_url: str | None = None,
    timeout: float | None = None,
) -> str:
    """Call Ollama /api/generate and return the full response text.

    Args:
        prompt: User prompt (e.g. code + "Explain this function").
        model: Model name (default from env OLLAMA_MODEL or llama3.2).
        system: Optional system prompt.
        base_url: Ollama base URL (default from env OLLAMA_HOST or localhost:11434).
        timeout: Request timeout in seconds.

    Returns:
        The generated text (response["response"]).

    Raises:
        RuntimeError: If Ollama is unreachable or returns an error.
    """
    base_url = (base_url or os.environ.get("OLLAMA_HOST") or DEFAULT_BASE_URL).rstrip("/")
    model = model or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL
    timeout = timeout if timeout is not None else DEFAULT_TIMEOUT

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if system:
        payload["system"] = system

    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(f"{base_url}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
    except httpx.ConnectError as e:
        raise RuntimeError(
            "Cannot connect to Ollama. Is it running? Start with: ollama serve"
        ) from e
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ollama API error: {e.response.status_code} {e.response.text}") from e
    except httpx.TimeoutException as e:
        raise RuntimeError(f"Ollama request timed out after {timeout}s") from e

    return data.get("response", "").strip()
