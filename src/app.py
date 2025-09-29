# Copyright (c) 2025 Splunk Inc.
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
import httpx

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params, MakeRequestParams
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.models.vault_attachment import VaultAttachment
from models.outputs.shared.main import APILinks
from models.outputs.domain_reputation.domain import DomainAttributes
from models.outputs.file_reputation.file import FileAttributes
from models.outputs.ip_reputation.ip import IPAttributes
from models.outputs.quotas.quota_models import (
    ApiRequestsDailyOutput,
    ApiRequestsHourlyOutput,
    ApiRequestsMonthlyOutput,
    CollectionsCreationMonthlyOutput,
    IntelligenceDownloadsMonthlyOutput,
    IntelligenceGraphsPrivateOutput,
    IntelligenceHuntingRulesOutput,
    IntelligenceRetrohuntJobsMonthlyOutput,
    IntelligenceSearchesMonthlyOutput,
    IntelligenceVtdiffCreationMonthlyOutput,
    MonitorStorageBytesOutput,
    MonitorStorageFilesOutput,
    MonitorUploadedBytesOutput,
    MonitorUploadedFilesOutput,
    PrivateScansMonthlyOutput,
    PrivateScansPerMinuteOutput,
)
from models.outputs.detonation.attributes import DetonateFileAttributes
from models.outputs.detonation.data import PollingData, MetaOutput
from models.outputs.url_reputation.url import URLAttributes
from typing import Optional
from cache import DataCache
import base64
import datetime
import time


from utils import sanitize_key_names

logger = getLogger()

# Error codes that should not cause the action to fail
PASS_ERROR_CODE = {
    400: "NotAvailableYet",
    404: "NotFoundError",
    409: "AlreadyExistsError",
}


class Asset(BaseAsset):
    apikey: str = AssetField(
        required=True, description="VirusTotal API key", sensitive=True
    )
    poll_interval: float = AssetField(
        required=False,
        description="Number of minutes to poll for a detonation result (Default: 5)",
        default=5.0,
    )
    waiting_time: float = AssetField(
        required=False,
        description="Number of seconds to wait before polling for a detonation result (Default: 0)",
        default=0.0,
    )
    rate_limit: bool = AssetField(
        required=False,
        description="Limit number of requests to 4 per minute",
        default=True,
    )
    timeout: float = AssetField(
        required=False,
        description="Request Timeout (Default: 30 seconds)",
        default=30.0,
    )
    cache_reputation_checks: bool = AssetField(
        required=False, description="Cache virustotal reputation checks", default=True
    )
    cache_expiration_interval: float = AssetField(
        required=False,
        description="Number of seconds until cached reputation checks expire. Any other value than positive integer will disable caching (Default: 3600 seconds)",
        default=3600.0,
    )
    cache_size: float = AssetField(
        required=False,
        description="Maximum number of entries in cache. Values of zero or less will not limit size and decimal value will be converted to floor value (Default: 1000)",
        default=1000.0,
    )

    def get_client(self) -> httpx.Client:
        headers = {
            "x-apikey": self.apikey,
            "Content-Type": "application/json",
        }
        return httpx.Client(
            base_url="https://www.virustotal.com/api/v3/",
            timeout=self.timeout,
            headers=headers,
        )


app = App(
    name="VirusTotal v3",
    app_type="reputation",
    logo="logo_virustotalv3.svg",
    logo_dark="logo_virustotalv3_dark.svg",
    product_vendor="VirusTotal",
    product_name="VirusTotal v3",
    publisher="Splunk",
    appid="3fe4875d-a4a7-47d3-9ef1-f9e63a6653a4",
    fips_compliant=True,
    asset_cls=Asset,
)


def _get_percentage(used: int, allowed: int) -> float:
    """Calculate percentage usage ratio"""
    if allowed == 0:
        return 0.0
    return round((used / allowed) * 100, 2)


def _get_cache_key(endpoint: str) -> str:
    call = app.actions_manager.get_action_identifier()
    if call == "url_reputation":
        tmp_value = endpoint[5:].encode(encoding="UTF-8")
        tmp_value = base64.urlsafe_b64decode(
            tmp_value + b"=" * (-len(tmp_value) % 4)
        ).decode()
        cache_key = "{}:{}".format(call, "urls/" + tmp_value)
    else:
        cache_key = f"{call}:{endpoint}"

    return cache_key


def _check_rate_limit(asset, count=1) -> None:
    """Check to see if the rate limit is within the "4 requests per minute" limit enforced by VirusTotal free tier.
    If the rate limit is exceeded, wait for the appropriate amount of time before making the request again.
    """
    if not asset.rate_limit:
        return
    logger.debug(f"Checking rate limit for the {count}th time")

    if count == 5:
        raise ActionFailure("Rate limit reached. Please try again later.")

    current_time = time.time()
    timestamps = app.actions_manager.asset_cache.get("rate_limit_timestamps", [])

    # Convert all timestamps to float and remove timestamps older than 60 seconds
    recent_timestamps = []
    for ts in timestamps:
        try:
            ts_float = float(ts)
            if current_time - ts_float < 60:
                recent_timestamps.append(ts_float)
        except (ValueError, TypeError):
            logger.debug(f"Skipping invalid timestamp: {ts}")
            continue
    app.actions_manager.asset_cache["rate_limit_timestamps"] = recent_timestamps

    # If we have 4 or more recent requests, wait until we can make another
    if len(recent_timestamps) >= 4:
        # Calculate how long to wait (until the oldest timestamp is 60+ seconds old)
        wait_time = 60 - (current_time - min(recent_timestamps))

        if wait_time > 0:
            logger.info(
                f"Rate limit reached. Waiting {wait_time:.2f} seconds before next request"
            )
            time.sleep(wait_time)

            return _check_rate_limit(asset, count + 1)

    logger.debug("Rate limit check complete.")


def _make_request(asset: Asset, method: str, endpoint: str, **kwargs) -> dict:
    if endpoint.startswith(("http://", "https://")):
        client = httpx.Client(
            timeout=asset.timeout,
            headers={
                "x-apikey": asset.apikey,
                "Content-Type": "application/json",
            },
        )
    else:
        client = asset.get_client()

    if asset.cache_reputation_checks and asset.cache_expiration_interval > 0:
        saved_cache = app.actions_manager.asset_cache.get("vt_cache")
        datacache = DataCache(
            asset.cache_expiration_interval, asset.cache_size, saved_cache
        )

        cache_key = _get_cache_key(endpoint)
        if entry := datacache.expire().search(cache_key):
            cached_status = entry[0]
            resp_json = entry[1]
            if cached_status != "success":
                raise ActionFailure(
                    f"Cached response for {endpoint} is not success with error {resp_json}"
                )
            return resp_json

    # Check rate limit before making request
    _check_rate_limit(asset)
    response = client.request(method, endpoint, **kwargs)
    response.raise_for_status()
    if asset.rate_limit:
        app.actions_manager.asset_cache["rate_limit_timestamps"].append(
            response.headers.get("Date", time.time())
        )

    resp_json = response.json()
    if asset.cache_reputation_checks and asset.cache_expiration_interval > 0:
        # we're no longer going to store failed responses in the cache
        datacache.add(cache_key, ("success", resp_json))
        app.actions_manager.asset_cache["vt_cache"] = datacache.cache

    return resp_json


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    client = asset.get_client()
    response = client.get("files/upload_url")

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise AssetMisconfiguration(
            "Failed to connect to VirusTotal. Please check the API key."
        ) from e

    logger.debug(f"VirusTotal response: {response.json()}")

    if "data" not in response.json():
        raise ActionFailure(
            "VirusTotal response did not contain any data. This is likely an issue with the VirusTotal service."
        )


class DomainReputationParams(Params):
    domain: str = Param(
        description="Domain to query", primary=True, cef_types=["domain"]
    )


class DomainReputationOutput(ActionOutput):
    id: str = OutputField(cef_types=["domain"], example_values=["test.com"])
    type: str = OutputField(example_values=["domain"])
    links: APILinks
    attributes: DomainAttributes


class DomainReputationSummary(ActionOutput):
    harmless: int
    malicious: int
    suspicious: int
    undetected: int


@app.action(description="Queries VirusTotal for domain info", action_type="investigate")
def domain_reputation(
    params: DomainReputationParams, soar: SOARClient, asset: Asset
) -> DomainReputationOutput:
    resp_json = _make_request(asset, "GET", f"domains/{params.domain}")

    logger.debug(f"VirusTotal response: {resp_json}")
    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for domain {params.domain}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    output = DomainReputationOutput(**sanitized_data)
    summary = DomainReputationSummary(
        harmless=output.attributes.last_analysis_stats.harmless,
        malicious=output.attributes.last_analysis_stats.malicious,
        suspicious=output.attributes.last_analysis_stats.suspicious,
        undetected=output.attributes.last_analysis_stats.undetected,
    )
    soar.set_summary(summary)
    return output


@app.make_request()
def http_action(params: MakeRequestParams, asset: Asset) -> MakeRequestOutput:
    client = asset.get_client()

    if params.endpoint.startswith("https") or params.endpoint.startswith("http"):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Please do not include the base url in the endpoint. The base url is already included in the asset."
        )

    request_kwargs = {"method": params.http_method, "url": params.endpoint}

    if params.query_params:
        request_kwargs["params"] = params.query_params
    if params.body:
        request_kwargs["json"] = params.body
    if params.headers:
        merged_headers = client.headers.copy()
        merged_headers.update(params.headers)
        request_kwargs["headers"] = merged_headers
    if params.verify_ssl:
        request_kwargs["verify"] = params.verify_ssl
    if params.timeout:
        request_kwargs["timeout"] = params.timeout

    _check_rate_limit(asset)
    response = client.request(**request_kwargs)
    response.raise_for_status()
    if asset.rate_limit:
        app.actions_manager.asset_cache["rate_limit_timestamps"].append(
            response.headers.get("Date", time.time())
        )

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )


class FileReputationParams(Params):
    hash: str = Param(
        description="File hash to query",
        primary=True,
        cef_types=["hash", "sha256", "sha1", "md5"],
    )


class FileReputationOutput(ActionOutput):
    id: str = OutputField(cef_types=["sha256"])
    type: str = OutputField(example_values=["file"])
    links: APILinks
    attributes: FileAttributes


@app.action(
    description="Queries VirusTotal for file reputation info", action_type="investigate"
)
def file_reputation(
    params: FileReputationParams, soar: SOARClient, asset: Asset
) -> FileReputationOutput:
    resp_json = _make_request(asset, "GET", f"files/{params.hash}")

    logger.debug(f"VirusTotal response: {resp_json}")
    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for file {params.hash}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    return FileReputationOutput(**sanitized_data)


class GetFileParams(Params):
    hash: str = Param(
        description="Hash of file to get",
        primary=True,
        cef_types=["hash", "sha256", "sha1", "md5"],
    )


@app.action(
    description="Downloads a file from VirusTotal and adds it to the vault",
    action_type="investigate",
)
def get_file(params: GetFileParams, soar: SOARClient, asset: Asset) -> ActionOutput:
    client = asset.get_client()
    _check_rate_limit(asset)
    response = client.get(f"files/{params.hash}/download")
    if asset.rate_limit:
        app.actions_manager.asset_cache["rate_limit_timestamps"].append(
            response.headers.get("Date", time.time())
        )

    response.raise_for_status()

    soar.vault.create_attachment(
        soar.get_executing_container_id(), response.content, params.hash
    )

    soar.set_message("File downloaded and added to the vault.")
    return ActionOutput()


class IpReputationParams(Params):
    ip: str = Param(description="IP to query", primary=True, cef_types=["ip", "ipv6"])


class IpReputationOutput(ActionOutput):
    id: str = OutputField(cef_types=["ip"], example_values=["2.3.4.5"])
    type: str = OutputField(example_values=["ip_address"])
    links: APILinks
    attributes: IPAttributes


@app.action(description="Queries VirusTotal for IP info", action_type="investigate")
def ip_reputation(
    params: IpReputationParams, soar: SOARClient, asset: Asset
) -> IpReputationOutput:
    resp_json = _make_request(asset, "GET", f"ips/{params.ip}")

    logger.debug(f"VirusTotal response: {resp_json}")
    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for IP {params.ip}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    return IpReputationOutput(**sanitized_data)


class UrlReputationParams(Params):
    url: str = Param(
        description="URL to query", primary=True, cef_types=["url", "domain"]
    )


class UrlReputationOutput(ActionOutput):
    attributes: URLAttributes
    id: str = OutputField(
        example_values=[
            "99999999eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"  # pragma: allowlist secret
        ]
    )
    links: APILinks
    type: str = OutputField(example_values=["url"])


@app.action(
    description="Queries VirusTotal for URL info (run this action after running detonate url)",
    action_type="investigate",
)
def url_reputation(
    params: UrlReputationParams, soar: SOARClient, asset: Asset
) -> UrlReputationOutput:
    resp_json = _make_request(asset, "GET", f"urls/{params.url}")

    logger.debug(f"VirusTotal response: {resp_json}")
    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for URL {params.url}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    return UrlReputationOutput(**sanitized_data)


class DetonateUrlParams(Params):
    url: str = Param(
        description="URL to detonate", primary=True, cef_types=["url", "domain"]
    )
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class DetonateUrlOutput(ActionOutput):
    attributes: URLAttributes
    data: Optional[PollingData]
    id: str = OutputField(
        example_values=[
            "e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"  # pragma: allowlist secret
        ]
    )
    links: APILinks
    meta: Optional[MetaOutput]
    type: str = OutputField(example_values=["url"])


@app.action(
    description="Load a URL to Virus Total and retrieve analysis results",
    action_type="investigate",
    verbose="<b>detonate url</b> will send a URL to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given URL has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def detonate_url(
    params: DetonateUrlParams, soar: SOARClient, asset: Asset
) -> DetonateUrlOutput:
    raise NotImplementedError()


class DetonateFileParams(Params):
    vault_id: str = Param(
        description="The Vault ID of the file to scan",
        primary=True,
        cef_types=["vault id", "sha1"],
    )
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class DetonateFileOutput(ActionOutput):
    vault_id: str
    attributes: DetonateFileAttributes
    data: Optional[PollingData]
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"  # pragma: allowlist secret
        ],
    )
    links: APILinks
    meta: Optional[MetaOutput]
    type: str = OutputField(example_values=["file"])


class DetonateSummary(ActionOutput):
    scan_id: str
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int


def poll_for_result(
    scan_id: str, poll_interval: float, wait_time: float, asset: Asset
) -> tuple[dict, DetonateSummary]:
    time.sleep(wait_time)
    # since we sleep for 1 minute, num_attempts is the number of minutes to poll
    num_attempts = poll_interval
    while num_attempts > 0:
        resp_json = _make_request(asset, "GET", f"analyses/{scan_id}")
        if isinstance(resp_json, dict):
            resp_json = sanitize_key_names(resp_json)

        if "data" in resp_json and resp_json.get("data", {}).get("attributes", {}).get(
            "results"
        ):
            attributes = resp_json["data"]["attributes"]

            summary = DetonateSummary(
                scan_id=scan_id,
                harmless=attributes.get("stats", {}).get("harmless", 0),
                malicious=attributes.get("stats", {}).get("malicious", 0),
                suspicious=attributes.get("stats", {}).get("suspicious", 0),
                timeout=attributes.get("stats", {}).get("timeout", 0),
                undetected=attributes.get("stats", {}).get("undetected", 0),
            )

            return resp_json, summary

        num_attempts -= 1
        time.sleep(60)

    raise ActionFailure(f"No result found for scan ID {scan_id}")


@app.view_handler(template="detonate_file_view.html")
def detonate_file_view(outputs: list[DetonateFileOutput]) -> dict:
    logger.debug(f"View handler called with {len(outputs)} outputs")
    result = {"results": []}
    for i, output in enumerate(outputs):
        logger.debug(
            f"Processing output {i}: vault_id={getattr(output, 'vault_id', 'MISSING')}"
        )
        result["results"].append(
            {
                "vault_id": output.vault_id,
                "sha256": output.id,
                "scan_id": output.data.id if output.data else None,
            }
        )

    result["container"] = {"id": app.soar_client.get_executing_container_id()}

    logger.debug(f"Detonate file view result: {result}")
    return result


@app.action(
    description="Upload a file to Virus Total and retrieve the analysis results",
    action_type="investigate",
    verbose="<b>detonate file</b> will send a file to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given file has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
    view_handler=detonate_file_view,
)
def detonate_file(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileOutput:
    vault_id = params.vault_id
    attachments = soar.vault.get_attachment(vault_id=vault_id)
    if len(attachments) == 0:
        raise ActionFailure(f"File {vault_id} not found in vault")
    if len(attachments) > 1:
        logger.info(
            f"Multiple files found in vault for {vault_id}. Choosing the first one."
        )
    attachment: VaultAttachment = attachments[0]
    file_name = attachment.name
    file_path = attachment.path
    file_hash = attachment.hash

    resp_json = _make_request(asset, "GET", f"files/{file_hash}")

    if resp_json.get("error", {}).get("code") in PASS_ERROR_CODE.values():
        with open(file_path, "rb") as file_handle:
            files = [("file", (file_name, file_handle, "application/octet-stream"))]
            if (attachment.size / 1000000) > 32:
                resp_json = _make_request(asset, "GET", "files/upload_url")
                if not (upload_url := resp_json.get("data", {})):
                    raise ActionFailure(f"No upload URL found for file {file_hash}")

                file_upload_json = _make_request(asset, "POST", upload_url, files=files)
            else:
                file_upload_json = _make_request(asset, "POST", "files", files=files)

        if not (scan_id := file_upload_json.get("data", {}).get("id")):
            raise ActionFailure(f"No scan ID found for file {file_hash}")

        output, summary = poll_for_result(
            scan_id, asset.poll_interval, params.wait_time or asset.waiting_time, asset
        )
        soar.set_summary(summary)
        return DetonateFileOutput(**output, vault_id=vault_id)

    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for file {file_hash}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    # if last_analysis_results exists, reorganize to support standard data path format of
    # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
    attributes = sanitized_data.get("attributes", {})
    if "last_analysis_results" in attributes:
        last_analysis_results = [
            {"vendor": vendor, **results}
            for vendor, results in attributes["last_analysis_results"].items()
        ]
        sanitized_data["attributes"]["last_analysis_results"] = last_analysis_results

    if "last_analysis_date" in attributes:
        new_scan_id = f"{attributes['md5']}:{attributes['last_analysis_date']}"
    else:
        new_scan_id = f"{attributes['md5']}:{attributes['last_submission_date']}"

    new_scan_id = base64.b64encode(new_scan_id.encode()).decode()

    if "last_analysis_stats" in attributes:
        summary = DetonateSummary(
            scan_id=new_scan_id,
            harmless=attributes["last_analysis_stats"]["harmless"],
            malicious=attributes["last_analysis_stats"]["malicious"],
            suspicious=attributes["last_analysis_stats"]["suspicious"],
            timeout=attributes["last_analysis_stats"]["timeout"],
            undetected=attributes["last_analysis_stats"]["undetected"],
        )
        soar.set_summary(summary)

    logger.debug(f"Sanitized data: {sanitized_data}")
    return DetonateFileOutput(**sanitized_data, vault_id=vault_id)


class GetReportParams(Params):
    scan_id: str = Param(
        description="Scan ID", primary=True, cef_types=["virustotal scan id"]
    )
    wait_time: float = Param(description="Number of seconds to wait", required=False)


@app.action(
    description="Get the results using the scan id from a detonate file or detonate url action",
    action_type="investigate",
    verbose="For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def get_report(params: GetReportParams, soar: SOARClient, asset: Asset) -> PollingData:
    scan_id = params.scan_id
    logger.info(f"Polling VirusTotal for report related to {scan_id}")
    resp_json, summary = poll_for_result(
        scan_id, asset.poll_interval, params.wait_time or asset.waiting_time, asset
    )
    soar.set_summary(summary)
    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for scan ID {scan_id}")
    logger.debug(f"Polling dataaaaa: {data}")
    return PollingData(**data)


class GetCachedEntriesOutput(ActionOutput):
    date_added: str
    date_expires: str
    key: str
    seconds_left: float


@app.action(description="Get listing of cached entries", action_type="investigate")
def get_cached_entries(
    params: Params, soar: SOARClient, asset: Asset
) -> list[GetCachedEntriesOutput]:
    saved_cache = app.actions_manager.asset_cache.get("vt_cache", {})

    datacache = DataCache(
        asset.cache_expiration_interval, asset.cache_size, saved_cache
    )
    return [
        GetCachedEntriesOutput(
            date_added=datetime.datetime.fromtimestamp(
                val_dict["timestamp"], datetime.timezone.utc
            ).isoformat(),
            date_expires=datetime.datetime.fromtimestamp(
                val_dict["timestamp"] + asset.cache_expiration_interval,
                datetime.timezone.utc,
            ).isoformat(),
            key=key,
            seconds_left=val_dict["timestamp"]
            + asset.cache_expiration_interval
            - time.time(),
        )
        for key, val_dict in datacache.cache.items()
    ]


class ClearCacheOutput(ActionOutput):
    status: str = OutputField(example_values=["success"])


@app.action(
    description="Clear all cached entries", action_type="generic", read_only=False
)
def clear_cache(params: Params, soar: SOARClient, asset: Asset) -> ClearCacheOutput:
    if "vt_cache" in app.actions_manager.asset_cache:
        app.actions_manager.asset_cache["vt_cache"] = {}
    return ClearCacheOutput(status="success")


class GetQuotasParams(Params):
    user_id: str = Param(description="The username or API key to use to fetch quotas")


class GetQuotasOutput(ActionOutput):
    api_requests_daily: ApiRequestsDailyOutput
    api_requests_hourly: ApiRequestsHourlyOutput
    api_requests_monthly: ApiRequestsMonthlyOutput
    collections_creation_monthly: CollectionsCreationMonthlyOutput
    intelligence_downloads_monthly: IntelligenceDownloadsMonthlyOutput
    intelligence_graphs_private: IntelligenceGraphsPrivateOutput
    intelligence_hunting_rules: IntelligenceHuntingRulesOutput
    intelligence_retrohunt_jobs_monthly: IntelligenceRetrohuntJobsMonthlyOutput
    intelligence_searches_monthly: IntelligenceSearchesMonthlyOutput
    intelligence_vtdiff_creation_monthly: IntelligenceVtdiffCreationMonthlyOutput
    monitor_storage_bytes: MonitorStorageBytesOutput
    monitor_storage_files: MonitorStorageFilesOutput
    monitor_uploaded_bytes: MonitorUploadedBytesOutput
    monitor_uploaded_files: MonitorUploadedFilesOutput
    private_scans_monthly: PrivateScansMonthlyOutput
    private_scans_per_minute: PrivateScansPerMinuteOutput


class GetQuotasSummaryOutput(ActionOutput):
    user_hourly_api_ratio: Optional[float]
    group_hourly_api_ratio: Optional[float]
    user_daily_api_ratio: Optional[float]
    group_daily_api_ratio: Optional[float]
    user_monthly_api_ratio: Optional[float]
    group_monthly_api_ratio: Optional[float]

    @classmethod
    def from_quotas_output(
        cls, quotas_output: "GetQuotasOutput"
    ) -> "GetQuotasSummaryOutput":
        """Create a summary from a GetQuotasOutput instance"""
        summary = cls()

        # User hourly API ratio
        if (
            hasattr(quotas_output.api_requests_hourly, "user")
            and quotas_output.api_requests_hourly.user
        ):
            summary.user_hourly_api_ratio = _get_percentage(
                quotas_output.api_requests_hourly.user.used,
                quotas_output.api_requests_hourly.user.allowed,
            )

        # Group hourly API ratio
        if (
            hasattr(quotas_output.api_requests_hourly, "group")
            and quotas_output.api_requests_hourly.group
        ):
            summary.group_hourly_api_ratio = _get_percentage(
                quotas_output.api_requests_hourly.group.used,
                quotas_output.api_requests_hourly.group.allowed,
            )

        # User daily API ratio
        if (
            hasattr(quotas_output.api_requests_daily, "user")
            and quotas_output.api_requests_daily.user
        ):
            summary.user_daily_api_ratio = _get_percentage(
                quotas_output.api_requests_daily.user.used,
                quotas_output.api_requests_daily.user.allowed,
            )

        # Group daily API ratio
        if (
            hasattr(quotas_output.api_requests_daily, "group")
            and quotas_output.api_requests_daily.group
        ):
            summary.group_daily_api_ratio = _get_percentage(
                quotas_output.api_requests_daily.group.used,
                quotas_output.api_requests_daily.group.allowed,
            )

        # User monthly API ratio
        if (
            hasattr(quotas_output.api_requests_monthly, "user")
            and quotas_output.api_requests_monthly.user
        ):
            summary.user_monthly_api_ratio = _get_percentage(
                quotas_output.api_requests_monthly.user.used,
                quotas_output.api_requests_monthly.user.allowed,
            )

        # Group monthly API ratio
        if (
            hasattr(quotas_output.api_requests_monthly, "group")
            and quotas_output.api_requests_monthly.group
        ):
            summary.group_monthly_api_ratio = _get_percentage(
                quotas_output.api_requests_monthly.group.used,
                quotas_output.api_requests_monthly.group.allowed,
            )

        return summary


@app.action(
    description="Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details",
    action_type="investigate",
    summary_type=GetQuotasSummaryOutput,
)
def get_quotas(
    params: GetQuotasParams, soar: SOARClient, asset: Asset
) -> GetQuotasOutput:
    quotas_endpoint = f"users/{params.user_id}/overall_quotas"
    resp_json = _make_request(asset, "GET", quotas_endpoint)
    logger.debug(f"VirusTotal response: {resp_json}")
    if not (data := resp_json.get("data")):
        raise ActionFailure(f"No data found for user {params.user_id}")

    sanitized_data = sanitize_key_names(data)
    get_quotas_output = GetQuotasOutput(**sanitized_data)

    get_quotas_summary = GetQuotasSummaryOutput.from_quotas_output(get_quotas_output)
    soar.set_summary(get_quotas_summary)

    return get_quotas_output


if __name__ == "__main__":
    app.cli()
