"""Tests for Splunk REST profile generation helpers."""

from detection_readiness.integrations.splunk_rest import (
    SplunkConnectionSettings,
    SplunkRestClient,
    build_profile_from_splunk,
)


def test_build_profile_from_splunk(monkeypatch):
    responses = {
        "/servicesNS/-/-/data/indexes": {
            "entry": [{"name": "main"}, {"name": "security"}],
        },
        "/servicesNS/-/-/data/props/sourcetypes": {
            "entry": [{"name": "azure:aad:signin"}],
        },
        "/servicesNS/-/-/datamodel/model": {
            "entry": [
                {
                    "name": "Authentication",
                    "content": {"acceleration": {"enabled": True}},
                }
            ],
        },
    }

    def fake_get_json(self, path, params=None):
        return responses[path]

    monkeypatch.setattr(SplunkRestClient, "get_json", fake_get_json)

    profile = build_profile_from_splunk(
        SplunkConnectionSettings(host="splunk.local", token="tkn"),
        environment_name="live",
        data_source_id="splunk_live",
    )

    source = profile.data_sources["splunk_live"]
    assert source.indexes == ["main", "security"]
    assert source.sourcetypes == ["azure:aad:signin"]
    assert source.query_modes["datamodel"] is True
    assert profile.datamodels["authentication"].available is True
