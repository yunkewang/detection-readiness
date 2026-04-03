"""Tests for the Splunk REST API client (unit tests — no live Splunk)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from detection_readiness.splunk.client import SplunkClient, SplunkConnectionError
from detection_readiness.splunk.datamodel_health import (
    DatamodelHealthResult,
    check_datamodel_health,
)


class TestSplunkClient:
    def test_init_strips_trailing_slash(self):
        client = SplunkClient(base_url="https://splunk:8089/", token="tok")
        assert client.base_url == "https://splunk:8089"

    def test_init_no_verify(self):
        client = SplunkClient(
            base_url="https://splunk:8089", token="tok", verify_ssl=False
        )
        assert client._ctx is not None

    @patch("detection_readiness.splunk.client.urllib.request.urlopen")
    def test_get_indexes(self, mock_urlopen):
        response_data = {"entry": [{"name": "main"}, {"name": "security"}]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = SplunkClient(base_url="https://splunk:8089", token="tok")
        indexes = client.get_indexes()
        assert len(indexes) == 2
        assert indexes[0]["name"] == "main"

    @patch("detection_readiness.splunk.client.urllib.request.urlopen")
    def test_get_sourcetypes(self, mock_urlopen):
        response_data = {
            "entry": [{"name": "syslog"}, {"name": "azure:aad:signin"}]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = SplunkClient(base_url="https://splunk:8089", token="tok")
        stypes = client.get_sourcetypes()
        assert "syslog" in stypes

    @patch("detection_readiness.splunk.client.urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        client = SplunkClient(base_url="https://splunk:8089", token="tok")
        with pytest.raises(SplunkConnectionError):
            client.get_indexes()


class TestDatamodelHealth:
    @patch("detection_readiness.splunk.datamodel_health.SplunkClient")
    def test_missing_datamodel(self, MockClient):
        client = MockClient()
        client.get_datamodels.return_value = []

        results = check_datamodel_health(client, ["Authentication"])
        assert len(results) == 1
        assert results[0].name == "Authentication"
        assert results[0].exists is False
        assert not results[0].healthy

    @patch("detection_readiness.splunk.datamodel_health.SplunkClient")
    def test_existing_accelerated_datamodel(self, MockClient):
        client = MockClient()
        client.get_datamodels.return_value = [{"name": "Endpoint"}]
        client.get_datamodel_acceleration.return_value = {
            "content": {
                "acceleration": "1",
                "acceleration.summary": {
                    "event_count": 50000,
                    "earliest_time": "2024-01-01T00:00:00",
                    "latest_time": "2024-06-01T00:00:00",
                    "is_complete": True,
                },
            }
        }

        results = check_datamodel_health(client, ["Endpoint"])
        assert len(results) == 1
        assert results[0].exists is True
        assert results[0].accelerated is True
        assert results[0].event_count == 50000
        assert results[0].healthy is True

    @patch("detection_readiness.splunk.datamodel_health.SplunkClient")
    def test_not_accelerated_warning(self, MockClient):
        client = MockClient()
        client.get_datamodels.return_value = [{"name": "Network_Traffic"}]
        client.get_datamodel_acceleration.return_value = {
            "content": {"acceleration": "0"}
        }

        results = check_datamodel_health(client, ["Network_Traffic"])
        assert results[0].accelerated is False
        assert any("not enabled" in w for w in results[0].warnings)

    def test_health_result_healthy_property(self):
        healthy = DatamodelHealthResult(
            name="test", exists=True, accelerated=True, event_count=100
        )
        assert healthy.healthy is True

        unhealthy = DatamodelHealthResult(
            name="test", exists=True, accelerated=False, event_count=100
        )
        assert unhealthy.healthy is False
