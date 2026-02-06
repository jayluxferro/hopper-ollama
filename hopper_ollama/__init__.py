"""HopperOllama: Ollama-powered analysis for Hopper Disassembler."""

from hopper_ollama.ollama_client import ollama_generate
from hopper_ollama.prompts import build_analysis_prompt

__all__ = ["ollama_generate", "build_analysis_prompt"]
