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

from models.outputs.shared.main import APILinks
from models.outputs.domain_reputation.domain import DomainAttributes
from models.outputs.file_reputation.file import FileAttributes
from models.outputs.ip_reputation.ip import IPAttributes

from utils import sanitize_key_names

logger = getLogger()


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


@app.action(description="Queries VirusTotal for domain info", action_type="investigate")
def domain_reputation(
    params: DomainReputationParams, soar: SOARClient, asset: Asset
) -> DomainReputationOutput:
    client = asset.get_client()

    response = client.get(f"domains/{params.domain}")
    response.raise_for_status()

    logger.debug(f"VirusTotal response: {response.json()}")
    if not (data := response.json().get("data")):
        raise ActionFailure(f"No data found for domain {params.domain}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    return DomainReputationOutput(**sanitized_data)


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

    response = client.request(**request_kwargs)
    response.raise_for_status()
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
    client = asset.get_client()

    response = client.get(f"files/{params.hash}")
    response.raise_for_status()

    logger.debug(f"VirusTotal response: {response.json()}")
    if not (data := response.json().get("data")):
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

    response = client.get(f"files/{params.hash}/download")
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
    client = asset.get_client()

    response = client.get(f"ip_addresses/{params.ip}")
    response.raise_for_status()

    logger.debug(f"VirusTotal response: {response.json()}")
    if not (data := response.json().get("data")):
        raise ActionFailure(f"No data found for IP {params.ip}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    return IpReputationOutput(**sanitized_data)


class UrlReputationParams(Params):
    url: str = Param(
        description="URL to query", primary=True, cef_types=["url", "domain"]
    )


class UrlReputationOutput(ActionOutput):
    # attributes: URLAttributes
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
    raise NotImplementedError()


class DetonateUrlParams(Params):
    url: str = Param(
        description="URL to detonate", primary=True, cef_types=["url", "domain"]
    )
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class DetonateUrlOutput(ActionOutput):
    # attributes: AttributesOutput
    # data: DataOutput
    id: str = OutputField(
        example_values=[
            "e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"  # pragma: allowlist secret
        ]
    )
    links: APILinks
    # meta: MetaOutput
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
    # attributes: AttributesOutput
    # data: DataOutput
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"  # pragma: allowlist secret
        ],
    )
    links: APILinks
    # meta: MetaOutput
    type: str = OutputField(example_values=["file"])


@app.action(
    description="Upload a file to Virus Total and retrieve the analysis results",
    action_type="investigate",
    verbose="<b>detonate file</b> will send a file to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given file has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def detonate_file(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileOutput:
    raise NotImplementedError()


class GetReportParams(Params):
    scan_id: str = Param(
        description="Scan ID", primary=True, cef_types=["virustotal scan id"]
    )
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class GetReportOutput(ActionOutput):
    # data: DataOutput
    # meta: MetaOutput
    pass


@app.action(
    description="Get the results using the scan id from a detonate file or detonate url action",
    action_type="investigate",
    verbose="For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    raise NotImplementedError()


class GetCachedEntriesOutput(ActionOutput):
    date_added: str
    date_expires: str
    key: str
    seconds_left: float


@app.action(description="Get listing of cached entries", action_type="investigate")
def get_cached_entries(
    params: Params, soar: SOARClient, asset: Asset
) -> GetCachedEntriesOutput:
    raise NotImplementedError()


class ClearCacheOutput(ActionOutput):
    status: str = OutputField(example_values=["success"])


@app.action(
    description="Clear all cached entries", action_type="generic", read_only=False
)
def clear_cache(params: Params, soar: SOARClient, asset: Asset) -> ClearCacheOutput:
    raise NotImplementedError()


class GetQuotasParams(Params):
    user_id: str = Param(description="The username or API key to use to fetch quotas")


class GetQuotasOutput(ActionOutput):
    # api_requests_daily: ApiRequestsDailyOutput
    # api_requests_hourly: ApiRequestsHourlyOutput
    # api_requests_monthly: ApiRequestsMonthlyOutput
    # collections_creation_monthly: CollectionsCreationMonthlyOutput
    # intelligence_downloads_monthly: IntelligenceDownloadsMonthlyOutput
    # intelligence_graphs_private: IntelligenceGraphsPrivateOutput
    # intelligence_hunting_rules: IntelligenceHuntingRulesOutput
    # intelligence_retrohunt_jobs_monthly: IntelligenceRetrohuntJobsMonthlyOutput
    # intelligence_searches_monthly: IntelligenceSearchesMonthlyOutput
    # intelligence_vtdiff_creation_monthly: IntelligenceVtdiffCreationMonthlyOutput
    # monitor_storage_bytes: MonitorStorageBytesOutput
    # monitor_storage_files: MonitorStorageFilesOutput
    # monitor_uploaded_bytes: MonitorUploadedBytesOutput
    # monitor_uploaded_files: MonitorUploadedFilesOutput
    # private_scans_monthly: PrivateScansMonthlyOutput
    # private_scans_per_minute: PrivateScansPerMinuteOutput
    pass


@app.action(
    description="Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details",
    action_type="investigate",
)
def get_quotas(
    params: GetQuotasParams, soar: SOARClient, asset: Asset
) -> GetQuotasOutput:
    raise NotImplementedError()


if __name__ == "__main__":
    app.cli()
