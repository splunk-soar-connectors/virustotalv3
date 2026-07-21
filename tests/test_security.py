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
import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from soar_sdk.exceptions import ActionFailure

import app
from app import DetonateFileParams, DetonateUrlParams, GetFileParams, get_file
from utils import (
    encode_api_path_segment,
    sanitize_url_object,
    stream_download_to_file,
    validate_upload_url,
    verify_downloaded_file,
)


def test_encode_api_path_segment_prevents_scope_changes():
    assert encode_api_path_segment("../users/me?x=1") == "..%2Fusers%2Fme%3Fx%3D1"


@pytest.mark.parametrize(
    "url",
    [
        "http://www.virustotal.com/upload",
        "https://example.com/upload",
        "https://www.virustotal.com:444/upload",
        "https://attacker@www.virustotal.com/upload",
    ],
)
def test_validate_upload_url_rejects_untrusted_origins(url):
    with pytest.raises(ActionFailure, match="untrusted"):
        validate_upload_url(url)


def test_validate_upload_url_accepts_virustotal_https_origin():
    url = "https://www.virustotal.com/_ah/upload/example"
    assert validate_upload_url(url) == url


def test_sanitize_url_object_removes_cookies_and_sensitive_headers():
    data = {
        "attributes": {
            "last_http_response_cookies": {"session": "secret"},
            "last_http_response_headers": {
                "Content-Type": "text/html",
                "Set-Cookie": "session=secret",
                "AUTHORIZATION": "Bearer secret",
            },
        }
    }

    sanitized = sanitize_url_object(data)

    assert "last_http_response_cookies" not in sanitized["attributes"]
    assert sanitized["attributes"]["last_http_response_headers"] == {
        "Content-Type": "text/html"
    }


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256"])
def test_verify_downloaded_file_accepts_matching_digest(algorithm):
    content = b"known sample"
    digest = hashlib.new(algorithm, content, usedforsecurity=False).hexdigest()

    verify_downloaded_file(digest, content)


def test_verify_downloaded_file_rejects_mismatched_content():
    digest = hashlib.sha256(b"expected").hexdigest()
    with pytest.raises(ActionFailure, match="does not match"):
        verify_downloaded_file(digest, b"substituted")


class StreamResponse:
    def __init__(self, chunks: list[bytes], content_length: str | None = None):
        self.chunks = chunks
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def iter_bytes(self, chunk_size: int):
        assert chunk_size > 0
        yield from self.chunks

    def raise_for_status(self) -> None:
        return None


class StreamContext:
    def __init__(self, response: StreamResponse):
        self.response = response

    def __enter__(self) -> StreamResponse:
        return self.response

    def __exit__(self, *_args) -> None:
        return None


class DownloadClient:
    def __init__(self, response: StreamResponse):
        self.response = response

    def stream(self, method: str, endpoint: str) -> StreamContext:
        assert method == "GET"
        assert endpoint.endswith("/download")
        return StreamContext(self.response)


class DownloadVault:
    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
        self.attachment_content = None

    def get_vault_tmp_dir(self) -> str:
        return str(self.temp_dir)

    def add_attachment(
        self, _container_id: int, file_path: str, _file_name: str
    ) -> str:
        self.attachment_content = Path(file_path).read_bytes()
        return "vault-id"


class DownloadSoar:
    def __init__(self, temp_dir: Path):
        self.vault = DownloadVault(temp_dir)
        self.message = None

    def get_executing_container_id(self) -> int:
        return 1

    def set_message(self, message: str) -> None:
        self.message = message


class DownloadAsset:
    rate_limit = False
    max_file_download_size_mib = 100.0

    def __init__(self, response: StreamResponse):
        self.response = response
        self.cache_state = {}

    def get_client(self) -> DownloadClient:
        return DownloadClient(self.response)


class DetonationAsset:
    poll_interval = 1
    waiting_time = 0


class DetonationSoar:
    def __init__(self, attachments=None):
        self.vault = SimpleNamespace(get_attachment=lambda **_kwargs: attachments or [])

    def set_summary(self, _summary) -> None:
        return None

    def set_message(self, _message: str) -> None:
        return None


class StopPolling(Exception):
    pass


class JsonResponse:
    def __init__(self):
        self.headers = {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"data": {"id": "response"}}


class RequestClient:
    def __init__(self):
        self.calls = []

    def request(self, method: str, endpoint: str, **kwargs) -> JsonResponse:
        self.calls.append((method, endpoint, kwargs))
        return JsonResponse()


class CacheAsset:
    cache_reputation_checks = True
    cache_expiration_interval = 3600
    cache_size = 10
    rate_limit = False

    def __init__(self):
        self.client = RequestClient()
        self.cache_state = {"rate_limit_timestamps": []}

    def get_client(self) -> RequestClient:
        return self.client


def test_stream_download_to_file_enforces_advertised_size(tmp_path: Path):
    digest = hashlib.sha256(b"small").hexdigest()
    response = StreamResponse([b"small"], content_length="6")

    with pytest.raises(ActionFailure, match="maximum download size"):
        stream_download_to_file(response, tmp_path / "download", digest, max_bytes=5)


def test_stream_download_to_file_enforces_observed_size(tmp_path: Path):
    content = b"too-large"
    digest = hashlib.sha256(content).hexdigest()
    response = StreamResponse([b"too-", b"large"], content_length="1")

    with pytest.raises(ActionFailure, match="maximum download size"):
        stream_download_to_file(response, tmp_path / "download", digest, max_bytes=5)


def test_stream_download_to_file_writes_verified_content(tmp_path: Path):
    content = b"streamed sample"
    digest = hashlib.sha256(content).hexdigest()
    destination = tmp_path / "download"
    response = StreamResponse(
        [b"streamed ", b"sample"], content_length=str(len(content))
    )

    assert stream_download_to_file(
        response, destination, digest, max_bytes=1024
    ) == len(content)
    assert destination.read_bytes() == content


def test_get_file_streams_to_vault_temp_and_removes_temp_dir(tmp_path: Path):
    content = b"streamed sample"
    digest = hashlib.sha256(content).hexdigest()
    soar = DownloadSoar(tmp_path)
    asset = DownloadAsset(StreamResponse([content], content_length=str(len(content))))

    get_file.__wrapped__(GetFileParams(hash=digest), soar, asset)

    assert soar.vault.attachment_content == content
    assert soar.message == "File downloaded and added to the vault."
    assert list(tmp_path.iterdir()) == []


def test_non_get_requests_are_never_cached():
    asset = CacheAsset()

    app._make_request(asset, "POST", "urls", data={"url": "https://example.com"})

    assert asset.client.calls == [
        ("POST", "urls", {"data": {"url": "https://example.com"}})
    ]
    assert "vt_cache" not in asset.cache_state


def test_detonate_url_reanalyzes_known_url_and_polls_returned_id(monkeypatch):
    calls = []
    url_id = base64.urlsafe_b64encode(b"https://example.com").decode().strip("=")

    def make_request(*args, **kwargs):
        calls.append((args[1], args[2], kwargs))
        return {"data": {"id": "known-url" if len(calls) == 1 else "analysis-url"}}

    def stop_polling(scan_id, *_args):
        assert scan_id == "analysis-url"
        raise StopPolling

    monkeypatch.setattr(app, "_make_request", make_request)
    monkeypatch.setattr(app, "poll_for_result", stop_polling)

    with pytest.raises(StopPolling):
        app.detonate_url.__wrapped__(
            DetonateUrlParams(url="https://example.com"),
            DetonationSoar(),
            DetonationAsset(),
        )

    assert calls == [
        (
            "GET",
            f"urls/{url_id}",
            {"raise_for_status": False, "cacheable": False},
        ),
        (
            "POST",
            f"urls/{url_id}/analyse",
            {},
        ),
    ]


def test_detonate_url_submits_unknown_url_and_polls_returned_id(monkeypatch):
    calls = []

    def make_request(*args, **kwargs):
        calls.append((args[1], args[2], kwargs))
        if len(calls) == 1:
            return {"error": {"code": "NotFoundError"}}
        return {"data": {"id": "submitted-url"}}

    def stop_polling(scan_id, *_args):
        assert scan_id == "submitted-url"
        raise StopPolling

    monkeypatch.setattr(app, "_make_request", make_request)
    monkeypatch.setattr(app, "poll_for_result", stop_polling)

    with pytest.raises(StopPolling):
        app.detonate_url.__wrapped__(
            DetonateUrlParams(url="https://example.com"),
            DetonationSoar(),
            DetonationAsset(),
        )

    assert calls[1] == ("POST", "urls", {"data": {"url": "https://example.com"}})


def test_detonate_file_reanalyzes_known_file_and_polls_returned_id(monkeypatch):
    file_hash = "a" * 64
    attachment = SimpleNamespace(name="sample", path="unused", hash=file_hash, size=1)
    calls = []

    def make_request(*args, **kwargs):
        calls.append((args[1], args[2], kwargs))
        return {"data": {"id": "known-file" if len(calls) == 1 else "analysis-file"}}

    def stop_polling(scan_id, *_args):
        assert scan_id == "analysis-file"
        raise StopPolling

    monkeypatch.setattr(app, "_make_request", make_request)
    monkeypatch.setattr(app, "poll_for_result", stop_polling)

    with pytest.raises(StopPolling):
        app.detonate_file.__wrapped__(
            DetonateFileParams(vault_id="vault-id"),
            DetonationSoar([attachment]),
            DetonationAsset(),
        )

    assert calls == [
        ("GET", f"files/{file_hash}", {"raise_for_status": False, "cacheable": False}),
        ("POST", f"files/{file_hash}/analyse", {}),
    ]


def test_detonate_actions_are_not_read_only():
    assert app.detonate_url.meta.read_only is False
    assert app.detonate_file.meta.read_only is False
