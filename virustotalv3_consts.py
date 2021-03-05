# File: virustotalv3_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


# Status/Progress Messages
VIRUSTOTAL_MSG_CREATED_URL = "Created Query URL"
VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED = "VirusTotal query for {object_name} '{object_value}' failed"
VIRUSTOTAL_MSG_CONNECTING = "Querying VirusTotal"
VIRUSTOTAL_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
VIRUSTOTAL_ERROR_CONNECTIVITY_TEST = "Connectivity test failed"
VIRUSTOTAL_MSG_CHECK_APIKEY = 'Please check your API KEY or the network connectivity'
VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE = "Server returned error code: {code}"
VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT = "Server returned error code: {code}. Exceeded API request rate limit. Try enabling rate limitation for this asset."
VIRUSTOTAL_SERVER_ERROR_FORBIDDEN = "Server returned error code: {code}. API key does not have permission for this action."
VIRUSTOTAL_SERVER_ERROR_NOT_FOUND = "Server returned error code: {code}. Requested file not found."
VIRUSTOTAL_SERVER_CONNECTION_ERROR = "Server connection error"
VIRUSTOTAL_MAX_POLLS_REACHED = "Reached max polling attempts. Try rerunning the action"
VIRUSTOTAL_EXPECTED_ERROR_MSG = "List index out of range"
VIRUSTOTAL_UNKNOWN_ERROR_CODE_MSG = "Error code unavailable"
VIRUSTOTAL_UNKNOWN_ERROR_MSG = "Unknown error occurred. Please check the asset configuration and|or action parameters."
VIRUSTOTAL_TYPE_ERROR_MSG = "Error occurred while connecting to the VirusTotal server. Please check the asset configuration and|or the action parameters."
VIRUSTOTAL_VALIDATE_INTEGER_MSG = "Please provide a valid integer value in the {key} parameter"

# Jsons used in params, result, summary etc.
VIRUSTOTAL_JSON_APIKEY = "apikey"
VIRUSTOTAL_JSON_RATE_LIMIT = "rate_limit"

# Other constants used in the connector
BASE_URL = 'https://www.virustotal.com/api/v3/'
FILE_REPUTATION_ENDPOINT = 'files/{id}'
FILE_TEST_CONN_ENDPOINT = 'files/upload_url'
FILE_REPORT_ENDPOINT = 'files'
GET_FILE_API_ENDPOINT = 'files/{id}/download'
URL_API_ENDPOINT = 'urls'
ANALYSES_ENDPOINT = 'analyses/{id}'
DOMAIN_API_ENDPOINT = 'domains/{id}'
IP_API_ENDPOINT = 'ip_addresses/{id}'
