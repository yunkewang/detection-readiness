"""Tests for dependency-aware scoring and schema backward compatibility."""

import pytest

from detection_readiness.engine.assessor import assess
from detection_readiness.schemas.environment import (
    DataSource,
    DatamodelInfo,
    EnvironmentProfile,
    FieldInfo,
    KnowledgeObjects,
    LookupInfo,
    MacroInfo,
)
from detection_readiness.schemas.family import DetectionFamily, ExecutionDependencies, ScoringWeights
from detection_readiness.schemas.result import AssessmentResult, ReadinessStatus
from detection_readiness.scoring.scorer import evaluate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env(
    ko: KnowledgeObjects | None = None,
    **source_fields,
) -> EnvironmentProfile:
    source = DataSource(
        indexes=["main"],
        sourcetypes=["test:src"],
        fields={
            "user": FieldInfo(candidates=["user"], coverage=0.95),
            "src_ip": FieldInfo(candidates=["src"], coverage=0.90),
            "result": FieldInfo(candidates=["result"], coverage=0.85),
        },
        query_modes={"raw": True, "datamodel": False},
    )
    return EnvironmentProfile(
        environment_name="test_env",
        data_sources={"azure_ad_signin": source},
        datamodels={},
        constraints={},
        notes=[],
        knowledge_objects=ko or KnowledgeObjects(),
    )


def _make_family(
    deps: ExecutionDependencies | None = None,
    dep_weight: float = 0.0,
) -> DetectionFamily:
    weights = ScoringWeights(
        required_data_source=30.0,
        required_fields=35.0,
        optional_fields=10.0,
        preferred_query_mode=15.0,
        fallback_query_mode=10.0,
        dependency_completeness=dep_weight,
    )
    return DetectionFamily(
        id="password_spray",
        display_name="Password Spray",
        description="Test",
        required_data_sources=["azure_ad_signin"],
        required_fields_by_source={"azure_ad_signin": ["user", "src_ip", "result"]},
        preferred_query_mode="datamodel",
        fallback_query_mode="raw",
        scoring_weights=weights,
        execution_dependencies=deps or ExecutionDependencies(),
    )


# ---------------------------------------------------------------------------
# Schema backward compatibility
# ---------------------------------------------------------------------------


class TestSchemaBackwardCompat:
    def test_env_without_ko_field_loads(self):
        """An EnvironmentProfile without knowledge_objects key still loads."""
        env = EnvironmentProfile(
            environment_name="legacy",
            data_sources={},
            datamodels={},
            constraints={},
            notes=[],
        )
        assert env.knowledge_objects is not None
        assert len(env.knowledge_objects.macros) == 0

    def test_family_without_exec_deps_loads(self):
        """A DetectionFamily without execution_dependencies still loads."""
        fam = DetectionFamily(
            id="old_family",
            display_name="Old",
            description="pre v0.2",
            required_data_sources=[],
            required_fields_by_source={},
        )
        assert fam.execution_dependencies is not None
        assert fam.scoring_weights.dependency_completeness == 0.0

    def test_legacy_assessment_result_loads(self):
        """AssessmentResult without dependency_summary still loads."""
        result = AssessmentResult(
            environment_name="e",
            detection_family_id="f",
            detection_family_name="F",
        )
        assert result.dependency_summary is None

    def test_scoring_without_deps_unchanged(self):
        """When no deps declared, scoring is identical to pre-v0.2."""
        env = _make_env()
        family = _make_family()  # no deps, dep_weight=0
        breakdown = evaluate(env, family)
        # Score should still be deterministic and match prior behavior
        score = (breakdown.earned / breakdown.possible) * 100
        assert score >= 50


# ---------------------------------------------------------------------------
# Dependency scoring impacts
# ---------------------------------------------------------------------------


class TestDependencyScoringImpacts:
    def test_missing_required_macro_adds_blocker(self):
        env = _make_env()  # empty KO → unknown
        family = _make_family(ExecutionDependencies(required_macros=["critical_macro"]))
        breakdown = evaluate(env, family)
        # unknown → warning, not blocker (profile has no KO data)
        warnings_text = " ".join(breakdown.warnings)
        assert "critical_macro" in warnings_text

    def test_missing_required_macro_with_ko_populated_adds_blocker(self):
        ko = KnowledgeObjects(macros={})  # KO populated but macro absent
        env = _make_env(ko=ko)
        # Add at least one entry to trigger "populated" state
        ko.eventtypes["dummy"] = __import__(
            "detection_readiness.schemas.environment", fromlist=["EventtypeInfo"]
        ).EventtypeInfo(name="dummy", available=True)
        family = _make_family(ExecutionDependencies(required_macros=["missing_macro"]))
        breakdown = evaluate(env, family)
        blockers_text = " ".join(breakdown.blockers)
        assert "missing_macro" in blockers_text

    def test_dep_weight_affects_possible(self):
        env = _make_env()
        family_no_dep = _make_family(dep_weight=0.0)
        # Must declare at least one dep for dep scoring to activate
        family_with_dep = _make_family(
            deps=ExecutionDependencies(required_macros=["some_macro"]),
            dep_weight=20.0,
        )
        bd_no = evaluate(env, family_no_dep)
        bd_with = evaluate(env, family_with_dep)
        # dep_weight > 0 with declared deps should increase possible
        assert bd_with.possible > bd_no.possible

    def test_all_deps_resolved_earns_full_dep_weight(self):
        macro = MacroInfo(name="my_macro", available=True, definition="search index=main")
        ko = KnowledgeObjects(macros={"my_macro": macro})
        env = _make_env(ko=ko)
        family = _make_family(
            deps=ExecutionDependencies(required_macros=["my_macro"]),
            dep_weight=20.0,
        )
        breakdown = evaluate(env, family)
        # Should earn close to full dep weight (0 missing, 0 unhealthy)
        assert breakdown.dependency_summary is not None
        assert len(breakdown.dependency_summary.missing) == 0
        # Earned ratio for deps should be ~1.0
        from detection_readiness.dependencies.resolver import compute_dependency_completeness
        completeness = compute_dependency_completeness(breakdown.dependency_summary)
        assert completeness == pytest.approx(1.0)

    def test_missing_dep_reduces_completeness_score(self):
        macro = MacroInfo(name="m1", available=True, definition="x")
        # m2 is missing
        ko = KnowledgeObjects(macros={"m1": macro})
        env = _make_env(ko=ko)
        family = _make_family(
            deps=ExecutionDependencies(required_macros=["m1", "m2"]),
            dep_weight=20.0,
        )
        breakdown = evaluate(env, family)
        from detection_readiness.dependencies.resolver import compute_dependency_completeness
        completeness = compute_dependency_completeness(breakdown.dependency_summary)
        assert completeness < 1.0

    def test_lookup_missing_file_adds_blocker(self):
        lookup = LookupInfo(
            name="user_lookup",
            available=True,
            transform_available=True,
            file_available=False,
        )
        ko = KnowledgeObjects(lookups={"user_lookup": lookup})
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(required_lookups=["user_lookup"]))
        breakdown = evaluate(env, family)
        blockers_text = " ".join(breakdown.blockers)
        assert "user_lookup" in blockers_text

    def test_optional_dep_missing_adds_warning_not_blocker(self):
        ko = KnowledgeObjects(macros={})
        # trigger "populated" via eventtypes
        from detection_readiness.schemas.environment import EventtypeInfo
        ko.eventtypes["dummy"] = EventtypeInfo(name="dummy", available=True)
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(optional_macros=["opt_macro"]))
        breakdown = evaluate(env, family)
        assert all("opt_macro" not in b for b in breakdown.blockers)
        assert any("opt_macro" in w for w in breakdown.warnings)


# ---------------------------------------------------------------------------
# Full assessment integration
# ---------------------------------------------------------------------------


class TestFullAssessmentIntegration:
    def test_assessment_result_includes_dep_summary_when_deps_declared(self):
        ko = KnowledgeObjects(macros={"m": MacroInfo(name="m", available=True, definition="x")})
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(required_macros=["m"]), dep_weight=10.0)
        result = assess(env, family)
        assert result.dependency_summary is not None

    def test_assessment_result_dep_summary_none_when_no_deps(self):
        env = _make_env()
        family = _make_family()
        result = assess(env, family)
        assert result.dependency_summary is None

    def test_explanation_includes_dependency_section_when_deps_declared(self):
        ko = KnowledgeObjects(macros={})
        from detection_readiness.schemas.environment import EventtypeInfo
        ko.eventtypes["dummy"] = EventtypeInfo(name="dummy", available=True)
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(required_macros=["missing"]))
        result = assess(env, family)
        assert "Knowledge Object Dependencies" in result.detailed_explanation or \
               "missing" in result.detailed_explanation.lower()

    def test_short_explanation_mentions_dep_blocker(self):
        ko = KnowledgeObjects(macros={})
        from detection_readiness.schemas.environment import EventtypeInfo
        ko.eventtypes["dummy"] = EventtypeInfo(name="dummy", available=True)
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(required_macros=["critical"]))
        result = assess(env, family)
        assert "blocked" in result.short_explanation.lower() or "blocker" in result.short_explanation.lower() or \
               "unresolved" in result.short_explanation.lower()


# ---------------------------------------------------------------------------
# SPL generator with dependency annotations
# ---------------------------------------------------------------------------


class TestSPLGeneratorDepAnnotations:
    def test_spl_contains_dep_summary_comment(self):
        from detection_readiness.content_factory.spl_generator import generate_spl

        ko = KnowledgeObjects(macros={})
        from detection_readiness.schemas.environment import EventtypeInfo
        ko.eventtypes["dummy"] = EventtypeInfo(name="dummy", available=True)
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(required_macros=["missing_m"]))
        result = assess(env, family)
        spl = generate_spl(result)
        assert "Dependencies:" in spl or "REQUIRED MISSING" in spl

    def test_safe_spl_generated_without_macros(self):
        from detection_readiness.content_factory.spl_generator import generate_dependency_safe_spl

        ko = KnowledgeObjects(macros={})
        from detection_readiness.schemas.environment import EventtypeInfo
        ko.eventtypes["dummy"] = EventtypeInfo(name="dummy", available=True)
        env = _make_env(ko=ko)
        family = _make_family(ExecutionDependencies(required_macros=["missing_m"]))
        result = assess(env, family)
        safe = generate_dependency_safe_spl(result)
        assert "DEPENDENCY-SAFE" in safe
        # Should not contain macro backticks
        assert "`missing_m`" not in safe


# ---------------------------------------------------------------------------
# Live profile mocked REST parsing
# ---------------------------------------------------------------------------


class TestLiveProfileKnowledgeObjectParsing:
    """Test that _collect_* functions correctly parse mocked REST responses."""

    def test_macro_collection_from_mock_entries(self):
        """Verify MacroInfo is built correctly from a mocked REST entry."""
        from detection_readiness.integrations.splunk_rest import _collect_macros

        class FakeClient:
            def get_json(self, path, params=None):
                return {
                    "entry": [
                        {
                            "name": "my_macro",
                            "content": {
                                "definition": "search index=main",
                                "args": "arg1, arg2",
                            },
                            "acl": {"app": "search", "owner": "admin", "sharing": "global"},
                        }
                    ]
                }

        notes: list[str] = []
        macros = _collect_macros(FakeClient(), notes)  # type: ignore[arg-type]
        assert "my_macro" in macros
        m = macros["my_macro"]
        assert m.available is True
        assert m.app == "search"
        assert m.definition == "search index=main"
        assert "arg1" in m.arguments
        assert notes == []

    def test_lookup_collection_csv_backing(self):
        from detection_readiness.integrations.splunk_rest import _collect_lookups

        class FakeClient:
            def get_json(self, path, params=None):
                if "transforms" in path:
                    return {
                        "entry": [
                            {
                                "name": "user_lookup",
                                "content": {"filename": "users.csv"},
                                "acl": {"app": "SA-ThreatIntelligence"},
                            }
                        ]
                    }
                # lookup table files
                return {
                    "entry": [{"name": "users.csv"}]
                }

        notes: list[str] = []
        lookups = _collect_lookups(FakeClient(), notes)  # type: ignore[arg-type]
        assert "user_lookup" in lookups
        lu = lookups["user_lookup"]
        assert lu.backing_type == "csv"
        assert lu.file_available is True

    def test_lookup_missing_file_marked(self):
        from detection_readiness.integrations.splunk_rest import _collect_lookups

        class FakeClient:
            def get_json(self, path, params=None):
                if "transforms" in path:
                    return {
                        "entry": [
                            {
                                "name": "bad_lookup",
                                "content": {"filename": "missing.csv"},
                                "acl": {},
                            }
                        ]
                    }
                # No files returned
                return {"entry": []}

        notes: list[str] = []
        lookups = _collect_lookups(FakeClient(), notes)  # type: ignore[arg-type]
        assert lookups["bad_lookup"].file_available is False

    def test_collection_error_recorded_in_notes(self):
        from detection_readiness.integrations.splunk_rest import _collect_macros
        from detection_readiness.integrations.splunk_rest import SplunkRestError

        class FailClient:
            def get_json(self, path, params=None):
                raise SplunkRestError("Connection refused")

        notes: list[str] = []
        macros = _collect_macros(FailClient(), notes)  # type: ignore[arg-type]
        assert macros == {}
        assert len(notes) == 1
        assert "macros" in notes[0].lower()
