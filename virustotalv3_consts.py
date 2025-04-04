# File: virustotalv3_consts.py
#
# Copyright (c) 2021-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Status/Progress Messages
VIRUSTOTAL_MSG_CREATED_URL = "Created Query URL"
VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED = "VirusTotal query for {object_name} '{object_value}' failed"
VIRUSTOTAL_SUCCESS_MSG_WITH_ERROR = "VirusTotal query for {object_name} '{object_value}' was \
    successfully executed but returned an '{error_code}' error code."
VIRUSTOTAL_MSG_CONNECTIVITY = "Querying VirusTotal"
VIRUSTOTAL_SUCCESS_CONNECTIVITY_TEST = "Test connectivity passed"
VIRUSTOTAL_ERROR_CONNECTIVITY_TEST = "Test connectivity failed"
VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE = "Server returned error code: {code}"
VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT = (
    "Server returned error code: {code}. Exceeded API request rate limit. Try enabling rate limitation for this asset."
)
VIRUSTOTAL_SERVER_ERROR_FORBIDDEN = "Server returned error code: {code}. API key does not have permission for this action."
VIRUSTOTAL_SERVER_ERROR_NOT_FOUND = "Server returned error code: {code}. Requested file not found."
VIRUSTOTAL_SERVER_CONNECTIVITY_ERROR = "Server connection error"
VIRUSTOTAL_MAX_POLLS_REACHED = "Reached max polling attempts. Try rerunning the action"
VIRUSTOTAL_EXPECTED_ERROR_MSG = "List index out of range"
VIRUSTOTAL_UNKNOWN_ERROR_CODE_MSG = "Error code unavailable"
VIRUSTOTAL_UNKNOWN_ERROR_MSG = "Unknown error occurred. Please check the asset configuration and|or action parameters."
VIRUSTOTAL_VALIDATE_INTEGER_MSG = "Please provide a valid integer value in the {key} parameter"

# Jsons used in params, result, summary etc.
VIRUSTOTAL_JSON_APIKEY = "apikey"  # pragma: allowlist secret
VIRUSTOTAL_JSON_RATE_LIMIT = "rate_limit"
VIRUSTOTAL_JSON_TIMEOUT = "timeout"
VIRUSTOTAL_JSON_ENABLE_REPUTATION_CHECK = "cache_reputation_checks"
VIRUSTOTAL_JSON_CACHE_EXPIRATION_INTERVAL = "cache_expiration_interval"
VIRUSTOTAL_JSON_CACHE_EXPIRATION_LENGTH = "cache_size"

# Other constants used in the connector
BASE_URL = "https://www.virustotal.com/api/v3/"
FILE_REPUTATION_ENDPOINT = "files/{id}"
URL_REPUTATION_ENDPOINT = "urls/{id}"
FILE_UPLOAD_URL_ENDPOINT = "files/upload_url"
FILE_REPORT_ENDPOINT = "files"
GET_FILE_API_ENDPOINT = "files/{id}/download"
URL_API_ENDPOINT = "urls"
ANALYSES_ENDPOINT = "analyses/{id}"
DOMAIN_API_ENDPOINT = "domains/{id}"
IP_API_ENDPOINT = "ip_addresses/{id}"
QUOTA_ENDPOINT = "users/{id}/overall_quotas"
DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_INTERVAL = 3600
DEFAULT_CACHE_SIZE = 1000

PASS_ERROR_CODE = {400: "NotAvailableYet", 404: "NotFoundError", 409: "AlreadyExistsError"}
