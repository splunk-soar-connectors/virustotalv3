# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0

"""Use real HTTPX clients so unsupported request options cannot pass silently."""

import json

import httpx
import pytest

import app


@pytest.fixture
def http_clients(monkeypatch):
    clients = []
    verification = []
    requests = []
    client_type = httpx.Client

    def handle(request):
        requests.append(request)
        status = 401 if request.url.path.endswith("/denied") else 200
        return httpx.Response(status, json={"data": {"id": "fixture"}})

    def create(**kwargs):
        verification.append(kwargs.get("verify", True))
        client = client_type(**kwargs, transport=httpx.MockTransport(handle))
        clients.append(client)
        return client

    monkeypatch.setattr(app.httpx, "Client", create)
    return clients, verification, requests


@pytest.mark.parametrize(
    "verify", [None, True, False], ids=["default", "enabled", "disabled"]
)
def test_make_request_configures_client_tls_and_preserves_request(http_clients, verify):
    clients, verification, requests = http_clients
    asset = app.Asset(apikey="fixture-api-key", rate_limit=False)
    values = dict(
        endpoint="domains/example.com",
        http_method="post",
        headers=json.dumps({"X-Fixture": "retained"}),
        query_parameters=json.dumps({"limit": 1}),
        body=json.dumps({"fixture": True}),
        timeout=7,
    )
    if verify is not None:
        values["verify_ssl"] = verify
    params = app.VirusTotalMakeRequestParams(**values)

    result = app.http_action.__wrapped__(params, asset)

    assert result.status_code == 200
    assert verification == [True if verify is None else verify]
    assert clients[0].is_closed
    assert len(requests) == 1
    request = requests[0]
    assert (
        request.url == "https://www.virustotal.com/api/v3/domains/example.com?limit=1"
    )
    assert request.method == "POST"
    assert request.headers["x-apikey"] == asset.apikey
    assert request.headers["X-Fixture"] == "retained"
    assert json.loads(request.content) == {"fixture": True}
    assert set(request.extensions["timeout"].values()) == {7}


def test_make_request_closes_client_when_vendor_returns_error(http_clients):
    clients, _, requests = http_clients
    asset = app.Asset(apikey="fixture-api-key", rate_limit=False)
    params = app.VirusTotalMakeRequestParams(
        endpoint="denied", http_method="get", verify_ssl=False
    )

    with pytest.raises(httpx.HTTPStatusError):
        app.http_action.__wrapped__(params, asset)

    assert len(requests) == 1
    assert clients[0].is_closed
