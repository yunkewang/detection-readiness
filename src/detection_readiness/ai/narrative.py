"""Optional AI narrative summary generation."""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen

from detection_readiness.schemas.result import AssessmentResult


class NarrativeError(RuntimeError):
    """Raised when narrative generation fails."""


def generate_narrative_summary(
    result: AssessmentResult,
    *,
    provider: str = "openai",
    model: str = "gpt-4.1-mini",
    timeout_seconds: int = 30,
) -> str:
    """Generate a concise narrative summary.

    Falls back to deterministic output if provider config is unavailable.
    """
    if provider != "openai":
        return _deterministic_summary(result)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _deterministic_summary(result)

    prompt = (
        "Summarize this detection-readiness assessment in 5 bullet points with clear risks and next steps.\n"
        f"Family: {result.detection_family_name}\n"
        f"Score: {result.readiness_score}/100\n"
        f"Status: {result.readiness_status.value}\n"
        f"Strategy: {result.recommended_query_strategy}\n"
        f"Blockers: {result.blockers}\n"
        f"Warnings: {result.warnings}\n"
        f"Assumptions: {result.assumptions}\n"
        f"Remediation: {result.remediation_suggestions}\n"
    )

    body = {
        "model": model,
        "input": prompt,
    }
    request = Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise NarrativeError(f"OpenAI narrative generation failed: {exc}") from exc

    text = data.get("output_text")
    if isinstance(text, str) and text.strip():
        return text.strip()

    return _deterministic_summary(result)


def _deterministic_summary(result: AssessmentResult) -> str:
    blockers = len(result.blockers)
    warnings = len(result.warnings)
    return (
        f"- {result.detection_family_name} readiness is {result.readiness_status.value} "
        f"at {result.readiness_score:.1f}/100.\n"
        f"- Recommended strategy is '{result.recommended_query_strategy or 'unknown'}'.\n"
        f"- Identified {blockers} blocker(s) and {warnings} warning(s).\n"
        "- Prioritize blocker remediation before content production rollout.\n"
        "- Re-run assessment after onboarding missing fields and query capabilities."
    )
