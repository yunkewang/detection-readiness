"""Tests for the SPL dependency extraction parser."""

from detection_readiness.dependencies.parser import (
    ExtractedDependencies,
    extract_dependencies,
    extract_macro_refs_from_definition,
)


class TestExtractMacros:
    def test_simple_macro(self):
        spl = "search index=main | `my_macro`"
        result = extract_dependencies(spl)
        assert "my_macro" in result.macros

    def test_macro_with_args(self):
        spl = "| `security_content_ctime(firstTime)`"
        result = extract_dependencies(spl)
        assert "security_content_ctime" in result.macros

    def test_multiple_macros(self):
        spl = "| `cim_Authentication_indexes` | `drop_dm_object_name(Authentication)`"
        result = extract_dependencies(spl)
        assert "cim_Authentication_indexes" in result.macros
        assert "drop_dm_object_name" in result.macros

    def test_no_macros(self):
        spl = "search index=main sourcetype=foo | stats count by user"
        result = extract_dependencies(spl)
        assert result.macros == []

    def test_duplicate_macros_deduped(self):
        spl = "| `my_macro` | `my_macro`"
        result = extract_dependencies(spl)
        assert result.macros.count("my_macro") == 1

    def test_macros_sorted(self):
        spl = "| `zzz_macro` | `aaa_macro`"
        result = extract_dependencies(spl)
        assert result.macros == sorted(result.macros)


class TestExtractEventtypes:
    def test_simple_eventtype(self):
        spl = "search eventtype=wineventlog-security"
        result = extract_dependencies(spl)
        assert "wineventlog-security" in result.eventtypes

    def test_quoted_eventtype(self):
        spl = 'search eventtype="login_failure"'
        result = extract_dependencies(spl)
        assert "login_failure" in result.eventtypes

    def test_eventtype_with_spaces(self):
        spl = "search eventtype = my_events"
        result = extract_dependencies(spl)
        assert "my_events" in result.eventtypes

    def test_no_eventtype(self):
        spl = "search index=main sourcetype=foo"
        result = extract_dependencies(spl)
        assert result.eventtypes == []


class TestExtractLookups:
    def test_lookup_command(self):
        spl = "| lookup user_details user OUTPUT email"
        result = extract_dependencies(spl)
        assert "user_details" in result.lookups

    def test_inputlookup(self):
        spl = "| inputlookup threat_intel.csv"
        result = extract_dependencies(spl)
        assert "threat_intel.csv" in result.lookups

    def test_outputlookup(self):
        spl = "| outputlookup risk_scores"
        result = extract_dependencies(spl)
        assert "risk_scores" in result.lookups

    def test_multiple_lookups(self):
        spl = "| lookup user_info uid | lookup geo_info src_ip"
        result = extract_dependencies(spl)
        assert "user_info" in result.lookups
        assert "geo_info" in result.lookups

    def test_no_lookups(self):
        spl = "search index=main | stats count"
        result = extract_dependencies(spl)
        assert result.lookups == []


class TestExtractDatamodels:
    def test_tstats_datamodel(self):
        spl = "| tstats count from datamodel=Authentication.Authentication"
        result = extract_dependencies(spl)
        assert "Authentication.Authentication" in result.datamodels

    def test_datamodel_equals(self):
        spl = "| datamodel Authentication search"
        result = extract_dependencies(spl)
        assert "Authentication" in result.datamodels

    def test_no_datamodel(self):
        spl = "search index=main | stats count"
        result = extract_dependencies(spl)
        assert result.datamodels == []


class TestExtractMLTK:
    def test_fit_command(self):
        spl = "| fit RandomForestClassifier label from * into my_model"
        result = extract_dependencies(spl)
        assert "RandomForestClassifier" in result.mltk_models

    def test_apply_command(self):
        spl = "| apply anomaly_model"
        result = extract_dependencies(spl)
        assert "anomaly_model" in result.mltk_models

    def test_no_mltk(self):
        spl = "search index=main | stats count"
        result = extract_dependencies(spl)
        assert result.mltk_models == []


class TestExtractSavedSearches:
    def test_savedsearch_command(self):
        spl = "| savedsearch My Supporting Search"
        result = extract_dependencies(spl)
        assert "My Supporting Search" in result.saved_searches

    def test_no_savedsearch(self):
        spl = "search index=main | stats count"
        result = extract_dependencies(spl)
        assert result.saved_searches == []


class TestExtractedDependenciesHelpers:
    def test_is_empty_true(self):
        result = ExtractedDependencies()
        assert result.is_empty()

    def test_is_empty_false(self):
        result = ExtractedDependencies(macros=["foo"])
        assert not result.is_empty()

    def test_all_names(self):
        result = ExtractedDependencies(macros=["m1"], lookups=["l1"])
        names = result.all_names()
        assert "m1" in names
        assert "l1" in names


class TestExtractMacroRefs:
    def test_macro_inside_definition(self):
        definition = "search index=main | `helper_macro` | eval x=1"
        refs = extract_macro_refs_from_definition(definition)
        assert "helper_macro" in refs

    def test_no_refs_in_definition(self):
        definition = "search index=main sourcetype=foo"
        refs = extract_macro_refs_from_definition(definition)
        assert refs == []

    def test_multiple_refs(self):
        definition = "| `macro_a` | `macro_b(arg)`"
        refs = extract_macro_refs_from_definition(definition)
        assert "macro_a" in refs
        assert "macro_b" in refs
