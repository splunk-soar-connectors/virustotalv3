# Copyright (c) 2025-2026 Splunk Inc.
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
from pathlib import Path
from urllib.parse import quote, urlsplit

from soar_sdk.exceptions import ActionFailure


VIRUSTOTAL_API_HOST = "www.virustotal.com"
SENSITIVE_RESPONSE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "www-authenticate",
}
DOWNLOAD_CHUNK_SIZE = 1024 * 1024


def encode_api_path_segment(value: str) -> str:
    """Encode caller-controlled data as exactly one URL path segment."""
    return quote(str(value), safe="")


def validate_upload_url(upload_url: str) -> str:
    """Allow large-file uploads only to the trusted VirusTotal HTTPS origin."""
    parsed = urlsplit(upload_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ActionFailure("VirusTotal returned an untrusted file upload URL") from exc
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname != VIRUSTOTAL_API_HOST
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ActionFailure("VirusTotal returned an untrusted file upload URL")
    return upload_url


def sanitize_url_object(data: dict) -> dict:
    """Remove credentials captured in a VirusTotal URL object's HTTP metadata."""
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return data

    attributes.pop("last_http_response_cookies", None)
    headers = attributes.get("last_http_response_headers")
    if isinstance(headers, dict):
        attributes["last_http_response_headers"] = {
            name: value
            for name, value in headers.items()
            if name.lower() not in SENSITIVE_RESPONSE_HEADERS
        }
    return data


def _get_hash_details(file_hash: str) -> tuple[str, str]:
    """Return the normalized expected digest and its supported algorithm."""
    normalized_hash = file_hash.strip().lower()
    algorithm = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(normalized_hash))
    if algorithm is None or any(
        char not in "0123456789abcdef" for char in normalized_hash
    ):
        raise ActionFailure("File hash must be an MD5, SHA-1, or SHA-256 digest")

    return normalized_hash, algorithm


def verify_downloaded_file_digest(file_hash: str, actual_hash: str) -> None:
    """Fail closed unless a downloaded file digest matches the requested digest."""
    normalized_hash, _algorithm = _get_hash_details(file_hash)
    if actual_hash != normalized_hash:
        raise ActionFailure(
            "Downloaded file content does not match the requested hash; refusing to vault it"
        )


def verify_downloaded_file(file_hash: str, content: bytes) -> None:
    """Fail closed unless downloaded bytes match the requested content digest."""
    normalized_hash, algorithm = _get_hash_details(file_hash)

    computed_hash = hashlib.new(algorithm, content, usedforsecurity=False).hexdigest()
    verify_downloaded_file_digest(normalized_hash, computed_hash)


def stream_download_to_file(
    response, file_path: Path, file_hash: str, max_bytes: int
) -> int:
    """Stream a download to disk while enforcing advertised and observed size limits."""
    if max_bytes <= 0:
        raise ActionFailure("Maximum file download size must be greater than zero")

    advertised_size = response.headers.get("Content-Length")
    if advertised_size is not None:
        try:
            advertised_bytes = int(advertised_size)
        except (TypeError, ValueError) as exc:
            raise ActionFailure(
                "VirusTotal returned an invalid Content-Length"
            ) from exc
        if advertised_bytes < 0 or advertised_bytes > max_bytes:
            raise ActionFailure(
                "VirusTotal file exceeds the configured maximum download size"
            )

    _normalized_hash, algorithm = _get_hash_details(file_hash)
    hasher = hashlib.new(algorithm, usedforsecurity=False)
    observed_bytes = 0

    with file_path.open("wb") as file_handle:
        for chunk in response.iter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE):
            observed_bytes += len(chunk)
            if observed_bytes > max_bytes:
                raise ActionFailure(
                    "VirusTotal file exceeds the configured maximum download size"
                )
            file_handle.write(chunk)
            hasher.update(chunk)

    verify_downloaded_file_digest(file_hash, hasher.hexdigest())
    return observed_bytes


def sanitize_key_names(data: dict) -> dict:
    """Sanitize dictionary keys to only contain alphanumeric characters and underscores.

    If a sanitized key contains multiple underscores in a row, collapse them into a single underscore.
    If a value is a dictionary, recursively sanitize its keys.
    """
    sanitized_data = {}
    for key, value in data.items():
        sanitized_key = "".join(char if char.isalnum() else "_" for char in key)
        while "__" in sanitized_key:
            sanitized_key = sanitized_key.replace("__", "_")

        while sanitized_key.startswith("_"):
            sanitized_key = sanitized_key[1:]
        while sanitized_key.endswith("_"):
            sanitized_key = sanitized_key[:-1]

        sanitized_value = value
        if isinstance(value, dict):
            sanitized_value = sanitize_key_names(value)

        sanitized_data[sanitized_key] = sanitized_value
    return sanitized_data
