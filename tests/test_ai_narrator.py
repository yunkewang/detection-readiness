"""Tests for the AI narrator module (without actual API calls)."""

import os
from unittest.mock import patch

import pytest

from detection_readiness.explain.ai_narrator import (
    AINarratorError,
    _extract_anthropic_text,
    generate_ai_narrative,
    is_available,
)
from detection_readiness.schemas.result import AssessmentResult, ReadinessStatus


def _make_result() -> AssessmentResult:
    return AssessmentResult(
        environment_name="test_env",
        detection_family_id="password_spray",
        detection_family_name="Password Spray Detection",
        readiness_score=75.0,
        readiness_status=ReadinessStatus.PARTIALLY_READY,
        blockers=[],
        warnings=["Some warning"],
        recommended_query_strategy="raw",
    )


class TestIsAvailable:
    def test_no_keys(self):
        with patch.dict(os.environ, {}, clear=True):
            assert is_available() is False

    def test_anthropic_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            assert is_available() is True

    def test_openai_key(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            assert is_available() is True


class TestExtractAnthropicText:
    def test_extracts_text_blocks(self):
        data = {
            "content": [
                {"type": "text", "text": "Hello "},
                {"type": "text", "text": "world"},
            ]
        }
        assert _extract_anthropic_text(data) == "Hello \nworld"

    def test_empty_content(self):
        assert _extract_anthropic_text({"content": []}) == ""


class TestGenerateNarrative:
    def test_no_provider_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            result = _make_result()
            with pytest.raises(AINarratorError, match="No AI provider"):
                generate_ai_narrative(result)

    def test_unknown_provider_raises(self):
        result = _make_result()
        with pytest.raises(AINarratorError, match="Unknown AI provider"):
            generate_ai_narrative(result, provider="unknown")

    def test_anthropic_no_key_raises(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=True):
            result = _make_result()
            with pytest.raises(AINarratorError):
                generate_ai_narrative(result, provider="anthropic")

    def test_openai_no_key_raises(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=True):
            result = _make_result()
            with pytest.raises(AINarratorError):
                generate_ai_narrative(result, provider="openai")
