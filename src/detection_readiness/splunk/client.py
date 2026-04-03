"""Splunk REST API client for live environment profiling.

This module provides a thin client around the Splunk REST API using only the
standard library (urllib) so there is no hard dependency on the Splunk SDK.
For production use, callers can also provide a ``requests.Session`` or
``splunklib`` service object via the adapter pattern.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class SplunkConnectionError(Exception):
    """Raised when the client cannot reach the Splunk instance."""


@dataclass
class SplunkClient:
    """Lightweight Splunk REST API client.

    Args:
        base_url: Splunk management URI, e.g. ``https://splunk:8089``.
        token: A Splunk bearer token (preferred) or session key.
        verify_ssl: Whether to verify TLS certificates.
    """

    base_url: str
    token: str
    verify_ssl: bool = True
    _ctx: ssl.SSLContext | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if not self.verify_ssl:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _request(
        self, method: str, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Make an authenticated request and return the JSON response."""
        url = f"{self.base_url}{path}"
        if params:
            params.setdefault("output_mode", "json")
            url = f"{url}?{urllib.parse.urlencode(params)}"
        else:
            url = f"{url}?output_mode=json"

        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")

        try:
            with urllib.request.urlopen(req, context=self._ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.URLError as exc:
            raise SplunkConnectionError(
                f"Failed to reach Splunk at {self.base_url}: {exc}"
            ) from exc

    def get(
        self, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return self._request("GET", path, params)

    # ------------------------------------------------------------------
    # High-level convenience methods
    # ------------------------------------------------------------------

    def get_indexes(self) -> list[dict[str, Any]]:
        """Return a list of index objects."""
        data = self.get("/services/data/indexes")
        return data.get("entry", [])

    def get_sourcetypes(self) -> list[str]:
        """Return a list of known sourcetype names."""
        data = self.get("/services/saved/sourcetypes", {"count": "0"})
        return [e["name"] for e in data.get("entry", [])]

    def get_datamodels(self) -> list[dict[str, Any]]:
        """Return a list of datamodel objects."""
        data = self.get("/services/datamodel/model")
        return data.get("entry", [])

    def get_datamodel_acceleration(self, model_name: str) -> dict[str, Any]:
        """Return acceleration info for a specific datamodel."""
        data = self.get(
            f"/services/datamodel/model/{urllib.parse.quote(model_name)}",
            {"summarize": "true"},
        )
        entries = data.get("entry", [])
        return entries[0] if entries else {}

    def run_oneshot_search(
        self, query: str, *, earliest: str = "-24h", latest: str = "now", max_count: int = 100
    ) -> list[dict[str, Any]]:
        """Run a oneshot search and return result rows.

        This uses the ``/services/search/jobs/export`` endpoint.
        """
        params = {
            "search": query if query.startswith("|") else f"search {query}",
            "earliest_time": earliest,
            "latest_time": latest,
            "max_count": str(max_count),
            "output_mode": "json",
        }
        data = self.get("/services/search/jobs/export", params)
        # Export returns results directly or under "results" key
        if isinstance(data, list):
            return data
        return data.get("results", [])

    def get_field_summary(
        self,
        index: str,
        sourcetype: str,
        *,
        earliest: str = "-24h",
        max_count: int = 10000,
    ) -> dict[str, dict[str, Any]]:
        """Return field summary statistics for an index/sourcetype pair.

        Uses ``| fieldsummary`` to get field names, counts, and distinct values.
        """
        query = (
            f'search index="{index}" sourcetype="{sourcetype}" '
            f"| head {max_count} | fieldsummary"
        )
        rows = self.run_oneshot_search(query, earliest=earliest)
        summary: dict[str, dict[str, Any]] = {}
        for row in rows:
            name = row.get("field", "")
            if name:
                summary[name] = {
                    "count": int(row.get("count", 0)),
                    "distinct_count": int(row.get("distinct_count", 0)),
                    "numeric_count": int(row.get("numeric_count", 0)),
                    "is_exact": row.get("is_exact", "0") == "1",
                    "values": row.get("values", ""),
                }
        return summary
