"""Tests for the dependency resolver."""

import pytest

from detection_readiness.dependencies.resolver import (
    build_blockers_from_summary,
    build_warnings_from_summary,
    compute_dependency_completeness,
    resolve_dependencies,
)
from detection_readiness.schemas.environment import (
    EventtypeInfo,
    KnowledgeObjects,
    LookupInfo,
    MLTKModelInfo,
    MacroInfo,
    SavedSearchInfo,
)
from detection_readiness.schemas.family import DetectionFamily, ExecutionDependencies, ScoringWeights


def _make_family(deps: ExecutionDependencies | None = None, **overrides) -> DetectionFamily:
    return DetectionFamily(
        id="test_family",
        display_name="Test Family",
        description="For testing",
        required_data_sources=["src"],
        required_fields_by_source={},
        execution_dependencies=deps or ExecutionDependencies(),
        **overrides,
    )


def _make_ko(**kwargs) -> KnowledgeObjects:
    return KnowledgeObjects(**kwargs)


class TestResolveMacros:
    def test_required_macro_present_and_healthy(self):
        ko = _make_ko(macros={"my_macro": MacroInfo(name="my_macro", available=True, definition="search index=main")})
        family = _make_family(ExecutionDependencies(required_macros=["my_macro"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.resolved) == 1
        assert len(summary.missing) == 0

    def test_required_macro_missing(self):
        # KO is "populated" (has some other entry) but the macro is absent → missing
        ko = _make_ko(
            macros={"other_macro": MacroInfo(name="other_macro", available=True, definition="x")},
        )
        family = _make_family(ExecutionDependencies(required_macros=["missing_macro"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.missing) == 1
        assert summary.missing[0].name == "missing_macro"
        assert summary.missing[0].required is True

    def test_optional_macro_missing_becomes_warning_not_blocker(self):
        ko = _make_ko(
            macros={"other_macro": MacroInfo(name="other_macro", available=True, definition="x")},
        )
        family = _make_family(ExecutionDependencies(optional_macros=["optional_macro"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.missing) == 1
        assert summary.missing[0].required is False

    def test_macro_with_empty_definition_is_unhealthy(self):
        ko = _make_ko(macros={"bad_macro": MacroInfo(name="bad_macro", available=True, definition="  ")})
        family = _make_family(ExecutionDependencies(required_macros=["bad_macro"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.unhealthy) == 1
        assert any("empty" in note.lower() for note in summary.unhealthy[0].notes)

    def test_macro_chain_broken(self):
        """Macro A depends on macro B which is missing."""
        ko = _make_ko(macros={
            "macro_a": MacroInfo(
                name="macro_a", available=True,
                definition="| `macro_b`",
                depends_on_macros=["macro_b"],
            ),
            # macro_b is NOT in ko
        })
        family = _make_family(ExecutionDependencies(required_macros=["macro_a"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.unhealthy) == 1
        assert any("macro_b" in note for note in summary.unhealthy[0].notes)

    def test_macro_chain_logged(self):
        """Chain A->B->C (all present) should be logged in dependency_chain."""
        ko = _make_ko(macros={
            "macro_a": MacroInfo(name="macro_a", available=True, definition="| `macro_b`",
                                  depends_on_macros=["macro_b"]),
            "macro_b": MacroInfo(name="macro_b", available=True, definition="| `macro_c`",
                                  depends_on_macros=["macro_c"]),
            "macro_c": MacroInfo(name="macro_c", available=True, definition="search index=main"),
        })
        family = _make_family(ExecutionDependencies(required_macros=["macro_a"]))
        summary = resolve_dependencies(family, ko)
        # All resolved
        assert len(summary.resolved) == 1
        assert len(summary.dependency_chain) >= 2

    def test_unknown_when_ko_empty(self):
        """When no KO data collected, deps should be marked unknown, not missing."""
        ko = _make_ko()  # completely empty
        family = _make_family(ExecutionDependencies(required_macros=["some_macro"]))
        summary = resolve_dependencies(family, ko)
        # Empty KO → unknown
        assert len(summary.unknown) == 1


class TestResolveEventtypes:
    def test_eventtype_present(self):
        ko = _make_ko(eventtypes={
            "winevent_security": EventtypeInfo(name="winevent_security", available=True, search="EventCode=4625")
        })
        family = _make_family(ExecutionDependencies(required_eventtypes=["winevent_security"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.resolved) == 1

    def test_eventtype_missing(self):
        # KO populated (has macros) but eventtype absent → missing
        ko = _make_ko(
            macros={"dummy": MacroInfo(name="dummy", available=True, definition="x")},
            eventtypes={},
        )
        family = _make_family(ExecutionDependencies(required_eventtypes=["missing_et"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.missing) == 1

    def test_eventtype_with_missing_macro_is_unhealthy(self):
        ko = _make_ko(
            eventtypes={
                "my_et": EventtypeInfo(
                    name="my_et", available=True,
                    search="| `missing_macro`",
                    depends_on_macros=["missing_macro"],
                )
            }
        )
        family = _make_family(ExecutionDependencies(required_eventtypes=["my_et"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.unhealthy) == 1

    def test_eventtype_empty_search_is_unhealthy(self):
        ko = _make_ko(eventtypes={"empty_et": EventtypeInfo(name="empty_et", available=True, search="")})
        family = _make_family(ExecutionDependencies(required_eventtypes=["empty_et"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.unhealthy) == 1


class TestResolveLookups:
    def test_lookup_present_and_file_ok(self):
        ko = _make_ko(lookups={"user_lookup": LookupInfo(
            name="user_lookup", available=True, transform_available=True, file_available=True
        )})
        family = _make_family(ExecutionDependencies(required_lookups=["user_lookup"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.resolved) == 1

    def test_lookup_missing_file_is_unhealthy(self):
        ko = _make_ko(lookups={"bad_lookup": LookupInfo(
            name="bad_lookup", available=True, transform_available=True, file_available=False
        )})
        family = _make_family(ExecutionDependencies(required_lookups=["bad_lookup"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.unhealthy) == 1
        assert any("backing" in n.lower() or "file" in n.lower() for n in summary.unhealthy[0].notes)

    def test_lookup_missing_transform_is_unhealthy(self):
        ko = _make_ko(lookups={"bad_lookup": LookupInfo(
            name="bad_lookup", available=True, transform_available=False, file_available=True
        )})
        family = _make_family(ExecutionDependencies(required_lookups=["bad_lookup"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.unhealthy) == 1

    def test_lookup_not_in_ko_is_missing(self):
        ko = _make_ko(
            macros={"dummy": MacroInfo(name="dummy", available=True, definition="x")},
            lookups={},
        )
        family = _make_family(ExecutionDependencies(required_lookups=["ghost_lookup"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.missing) == 1


class TestResolveMLTK:
    def test_mltk_model_present(self):
        ko = _make_ko(mltk_models={"my_model": MLTKModelInfo(name="my_model", available=True)})
        family = _make_family(ExecutionDependencies(required_mltk_models=["my_model"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.resolved) == 1

    def test_mltk_model_missing(self):
        ko = _make_ko()
        family = _make_family(ExecutionDependencies(required_mltk_models=["anomaly_model"]))
        summary = resolve_dependencies(family, ko)
        # empty KO → unknown
        assert len(summary.unknown) == 1


class TestResolveSavedSearches:
    def test_saved_search_present(self):
        ko = _make_ko(saved_searches={"base_search": SavedSearchInfo(name="base_search", available=True)})
        family = _make_family(ExecutionDependencies(required_saved_searches=["base_search"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.resolved) == 1

    def test_saved_search_missing(self):
        ko = _make_ko(
            macros={"dummy": MacroInfo(name="dummy", available=True, definition="x")},
            saved_searches={},
        )
        family = _make_family(ExecutionDependencies(required_saved_searches=["missing_ss"]))
        summary = resolve_dependencies(family, ko)
        assert len(summary.missing) == 1


class TestSPLTemplateAutoExtract:
    def test_spl_template_extracts_macros(self):
        """Macros in spl_template are treated as optional deps and checked."""
        ko = _make_ko(macros={"helper": MacroInfo(name="helper", available=True, definition="eval x=1")})
        family = _make_family(ExecutionDependencies(spl_template="| `helper` | stats count"))
        summary = resolve_dependencies(family, ko)
        # 'helper' extracted as optional from template, found in ko
        resolved_names = [d.name for d in summary.resolved]
        assert "helper" in resolved_names

    def test_explicit_required_overrides_template_optional(self):
        """Macros listed as required_macros stay required even if also in template."""
        ko = _make_ko()
        family = _make_family(ExecutionDependencies(
            required_macros=["critical_macro"],
            spl_template="| `critical_macro` | stats count",
        ))
        summary = resolve_dependencies(family, ko)
        # empty KO → unknown, but required=True since it was in required_macros
        required_unknown = [d for d in summary.unknown if d.required]
        assert any(d.name == "critical_macro" for d in required_unknown)


class TestBlockersAndWarnings:
    def test_required_missing_becomes_blocker(self):
        ko = _make_ko(lookups={"good_lookup": LookupInfo(name="good_lookup", available=True)})
        family = _make_family(ExecutionDependencies(
            required_macros=["missing_macro"],
            required_lookups=["good_lookup"],
        ))
        summary = resolve_dependencies(family, ko)
        blockers = build_blockers_from_summary(summary)
        # lookup populated → missing_macro is missing (lookup present proves KO is populated)
        assert any("missing_macro" in b for b in blockers)

    def test_optional_missing_becomes_warning(self):
        ko = _make_ko(
            macros={"other": MacroInfo(name="other", available=True, definition="x")},
        )
        family = _make_family(ExecutionDependencies(optional_macros=["opt_macro"]))
        summary = resolve_dependencies(family, ko)
        warnings = build_warnings_from_summary(summary)
        assert any("opt_macro" in w for w in warnings)

    def test_unknown_becomes_warning(self):
        ko = _make_ko()
        family = _make_family(ExecutionDependencies(required_macros=["unverified"]))
        summary = resolve_dependencies(family, ko)
        warnings = build_warnings_from_summary(summary)
        assert any("unverified" in w for w in warnings)


class TestComputeCompleteness:
    def test_all_resolved_is_1(self):
        ko = _make_ko(macros={"m": MacroInfo(name="m", available=True, definition="search")})
        family = _make_family(ExecutionDependencies(required_macros=["m"]))
        summary = resolve_dependencies(family, ko)
        assert compute_dependency_completeness(summary) == pytest.approx(1.0)

    def test_required_missing_reduces_score(self):
        ko = _make_ko()  # empty → unknown
        family = _make_family(ExecutionDependencies(required_macros=["m1", "m2"]))
        summary = resolve_dependencies(family, ko)
        # unknown → 50% credit
        score = compute_dependency_completeness(summary)
        assert 0.0 < score < 1.0

    def test_no_deps_is_1(self):
        ko = _make_ko()
        family = _make_family()
        summary = resolve_dependencies(family, ko)
        assert compute_dependency_completeness(summary) == pytest.approx(1.0)


class TestAllRequiredResolved:
    def test_true_when_all_resolved(self):
        ko = _make_ko(macros={"m": MacroInfo(name="m", available=True, definition="x")})
        family = _make_family(ExecutionDependencies(required_macros=["m"]))
        summary = resolve_dependencies(family, ko)
        assert summary.all_required_resolved

    def test_false_when_required_missing(self):
        ko = _make_ko(macros={"m": MacroInfo(name="m", available=True, definition="x")})
        family = _make_family(ExecutionDependencies(required_macros=["m", "missing"]))
        summary = resolve_dependencies(family, ko)
        assert not summary.all_required_resolved
