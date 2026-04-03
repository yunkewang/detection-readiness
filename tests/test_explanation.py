"""Tests for explanation generation."""

from detection_readiness.explain.explainer import (
    generate_detailed_explanation,
    generate_short_explanation,
)
from detection_readiness.schemas.result import (
    AssessmentResult,
    DataSourceReadiness,
    FieldReadiness,
    ReadinessStatus,
)


def _make_result(**overrides) -> AssessmentResult:
    defaults = dict(
        environment_name="test_env",
        detection_family_id="password_spray",
        detection_family_name="Password Spray Detection",
        evaluated_data_sources=[
            DataSourceReadiness(
                source="azure_ad_signin",
                present=True,
                indexes=["idx"],
                fields=[
                    FieldReadiness(field="user", present=True, coverage=0.95, required=True),
                    FieldReadiness(field="src_ip", present=True, coverage=0.90, required=True),
                ],
            )
        ],
        readiness_score=75.0,
        readiness_status=ReadinessStatus.PARTIALLY_READY,
        blockers=["Missing field 'result'."],
        warnings=["Low coverage on src_ip."],
        assumptions=["Field names are not normalized."],
        recommended_query_strategy="raw",
        remediation_suggestions=["Map ResultType to result."],
    )
    defaults.update(overrides)
    return AssessmentResult(**defaults)


class TestShortExplanation:
    def test_contains_environment_name(self):
        result = _make_result()
        text = generate_short_explanation(result)
        assert "test_env" in text

    def test_contains_status(self):
        result = _make_result()
        text = generate_short_explanation(result)
        assert "partially ready" in text

    def test_contains_score(self):
        result = _make_result()
        text = generate_short_explanation(result)
        assert "75" in text

    def test_ready_status_label(self):
        result = _make_result(readiness_status=ReadinessStatus.READY, readiness_score=90)
        text = generate_short_explanation(result)
        assert "ready" in text.lower()


class TestDetailedExplanation:
    def test_contains_sections(self):
        result = _make_result()
        text = generate_detailed_explanation(result)
        assert "Data Sources" in text
        assert "Blockers" in text
        assert "Warnings" in text
        assert "Assumptions" in text
        assert "Remediation" in text

    def test_no_blockers_section_when_empty(self):
        result = _make_result(blockers=[])
        text = generate_detailed_explanation(result)
        assert "Blockers" not in text

    def test_field_details(self):
        result = _make_result()
        text = generate_detailed_explanation(result)
        assert "user" in text
        assert "95%" in text
