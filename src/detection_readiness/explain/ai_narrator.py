"""Optional AI-generated narrative summaries.

Uses the Anthropic API (Claude) or OpenAI API to generate rich narrative
explanations from assessment results. This module is entirely optional — the
core tool works without it.

Set the ``ANTHROPIC_API_KEY`` or ``OPENAI_API_KEY`` environment variable to
enable AI narration.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from detection_readiness.schemas.result import AssessmentResult

_SYSTEM_PROMPT = (
    "You are a detection engineering advisor. Given a structured readiness "
    "assessment result for a Splunk environment, write a clear, concise, and "
    "actionable narrative summary. Address the detection engineer directly. "
    "Focus on what matters: blockers, key gaps, recommended next steps, and "
    "the overall readiness posture. Keep it under 300 words."
)


class AINarratorError(Exception):
    """Raised when AI narration fails."""


def generate_ai_narrative(
    result: AssessmentResult,
    *,
    provider: str = "auto",
) -> str:
    """Generate an AI-powered narrative summary of an assessment result.

    Args:
        result: The structured assessment result to narrate.
        provider: ``"anthropic"``, ``"openai"``, or ``"auto"`` (tries
            Anthropic first, then OpenAI).

    Returns:
        A narrative string from the AI provider.

    Raises:
        AINarratorError: If no API key is configured or the request fails.
    """
    payload = result.model_dump_json(indent=2)

    if provider == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        else:
            raise AINarratorError(
                "No AI provider configured. Set ANTHROPIC_API_KEY or "
                "OPENAI_API_KEY to enable AI narration."
            )

    if provider == "anthropic":
        return _call_anthropic(payload)
    elif provider == "openai":
        return _call_openai(payload)
    else:
        raise AINarratorError(f"Unknown AI provider: {provider}")


def is_available() -> bool:
    """Return True if an AI provider is configured."""
    return bool(
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    )


def _call_anthropic(assessment_json: str) -> str:
    """Call the Anthropic Messages API."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise AINarratorError("ANTHROPIC_API_KEY is not set.")

    body = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "system": _SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Here is the detection readiness assessment result:\n\n"
                    f"```json\n{assessment_json}\n```\n\n"
                    "Write a narrative summary for the detection engineer."
                ),
            }
        ],
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "Anthropic-Version": "2023-06-01",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return _extract_anthropic_text(data)
    except urllib.error.URLError as exc:
        raise AINarratorError(f"Anthropic API request failed: {exc}") from exc


def _call_openai(assessment_json: str) -> str:
    """Call the OpenAI Chat Completions API."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise AINarratorError("OPENAI_API_KEY is not set.")

    body = json.dumps({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Here is the detection readiness assessment result:\n\n"
                    f"```json\n{assessment_json}\n```\n\n"
                    "Write a narrative summary for the detection engineer."
                ),
            },
        ],
        "max_tokens": 1024,
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return data["choices"][0]["message"]["content"]
    except urllib.error.URLError as exc:
        raise AINarratorError(f"OpenAI API request failed: {exc}") from exc


def _extract_anthropic_text(data: dict[str, Any]) -> str:
    """Extract text from an Anthropic Messages API response."""
    content = data.get("content", [])
    texts = [block["text"] for block in content if block.get("type") == "text"]
    return "\n".join(texts)
