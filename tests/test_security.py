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
import hashlib

import pytest
from soar_sdk.exceptions import ActionFailure

from utils import (
    encode_api_path_segment,
    sanitize_url_object,
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
