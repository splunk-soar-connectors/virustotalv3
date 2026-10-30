# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

import app


@pytest.fixture
def analysis():
    return {
        "id": "test-analysis",
        "type": "analysis",
        "links": {"self": "https://www.virustotal.com/api/v3/analyses/test-analysis"},
        "attributes": {
            "date": 1613651763,
            "status": "completed",
            "results": {
                "Test Engine": {"category": "harmless", "result": "clean"},
            },
            "stats": {
                "harmless": 1,
                "malicious": 0,
                "suspicious": 0,
                "timeout": 0,
                "undetected": 0,
            },
        },
    }


@pytest.mark.parametrize("state", ["completed", "queued", "http_error"])
def test_get_report_handles_analysis_response(state, analysis, monkeypatch):
    calls = []

    def respond(request):
        calls.append((request.method, request.url.path))
        if state == "http_error":
            return httpx.Response(
                503, json={"error": {"code": "ServiceUnavailableError"}}
            )
        if state == "queued":
            analysis["attributes"].update(status="queued", results={})
        return httpx.Response(200, json={"data": analysis})

    monkeypatch.setattr(app.time, "sleep", lambda _seconds: None)
    soar = Mock()
    with httpx.Client(
        base_url="https://www.virustotal.com/api/v3/",
        transport=httpx.MockTransport(respond),
    ) as client:
        asset = SimpleNamespace(
            get_client=lambda: client,
            cache_reputation_checks=False,
            rate_limit=False,
            poll_interval=1,
            waiting_time=0,
        )
        params = app.GetReportParams(scan_id="test-analysis")
        if state == "completed":
            report = app.get_report.__wrapped__(params, soar, asset)
            assert report.id == analysis["id"]
            assert report.type == "analysis"
            assert report.attributes.status == "completed"
            assert report.attributes.stats.harmless == 1
            summary = soar.set_summary.call_args.args[0]
            assert summary.scan_id == report.id
            assert summary.harmless == 1
            soar.set_message.assert_called_once_with(summary.get_message())
        elif state == "queued":
            with pytest.raises(
                ActionFailure, match="No result found for scan ID test-analysis"
            ):
                app.get_report.__wrapped__(params, soar, asset)
            soar.set_summary.assert_not_called()
        else:
            with pytest.raises(httpx.HTTPStatusError):
                app.get_report.__wrapped__(params, soar, asset)
            soar.set_summary.assert_not_called()

    assert calls == [("GET", "/api/v3/analyses/test-analysis")]
