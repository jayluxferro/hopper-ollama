"""Prompt templates for Hopper + Ollama analysis. No Hopper dependencies."""

ANALYSIS_TYPES = ("explain", "summarize", "suggest_name", "pattern")

SYSTEM_PROMPT = """You are a reverse-engineering assistant. You receive decompiled code or assembly from Hopper Disassembler. Answer concisely and in plain language. Do not repeat the code back."""


def build_analysis_prompt(
    decompiled: str | None,
    assembly: str | None,
    procedure_name: str | None,
    address: str,
    analysis_type: str = "explain",
    custom_question: str | None = None,
) -> str:
    """Build the user prompt for Ollama from Hopper context.

    Args:
        decompiled: Decompiled C (or None).
        assembly: Disassembly (or None).
        procedure_name: Name/label of the procedure.
        address: Hex address string (e.g. 0x1000).
        analysis_type: One of explain, summarize, suggest_name, pattern.
        custom_question: If set, used instead of analysis_type for the question.

    Returns:
        Full user prompt string.
    """
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
