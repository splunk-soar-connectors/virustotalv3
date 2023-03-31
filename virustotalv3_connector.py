# File: virustotalv3_connector.py
#
# Copyright (c) 2021-2023 Splunk Inc.
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
# Phantom imports
import base64
import calendar
import datetime
import ipaddress
import json
# Other imports used by this connector
import os
import re
import shutil
import sys
import time
import uuid
from copy import deepcopy as deepcopy

import magic
import phantom.app as phantom
import phantom.rules as ph_rules
# import hashlib
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.app import ActionResult, BaseConnector
from phantom.vault import Vault

# THIS Connector imports
from virustotalv3_consts import *
# for reputation check caching
from virustotalv3_DataCache import DataCache as datacache


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class VirustotalV3Connector(BaseConnector):

    MAGIC_FORMATS = [
      (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
      (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
      (re.compile('^PDF '), ['pdf'], '.pdf'),
      (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
      (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
      (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    def __init__(self):

        # Call the BaseConnectors init first
        super(VirustotalV3Connector, self).__init__()

        self._state = None
        self._apikey = None
        self._rate_limit = None
        self._verify_ssl = None
        self._poll_interval = None
        self._wait_time = None
        self._headers = dict()
        self._timeout = None

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = VIRUSTOTAL_UNKNOWN_ERROR_MSG

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.error_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_VALIDATE_INTEGER_MSG.format(key=key)), None
                parameter = int(parameter)

            except Exception:
                return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_VALIDATE_INTEGER_MSG.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR,
                                                "Please provide a valid non-negative integer value in the {} parameter".format(key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR,
                                                "Please provide non-zero positive integer in {}".format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):

        if (200 <= response.status_code < 205):
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            self.save_progress('Cannot parse JSON')
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", e), None)

        if (200 <= r.status_code < 205):
            return RetVal(phantom.APP_SUCCESS, resp_json)

        error_info = resp_json.get('error', {})
        if error_info.get('code') and error_info.get('message'):
            error_details = {
                'message': error_info.get('code'),
                'detail': error_info.get('message')
            }
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   "Error from server, Status Code: {0} data returned: {1}".format
                                                   (r.status_code, error_details)), resp_json)
        else:
            return RetVal( action_result.set_status(phantom.APP_ERROR,
                                                    "Error from server, Status Code: {0} data returned: {1}".format
                                                    (r.status_code, r.text.replace('{', '{{').replace('}', '}}'))), resp_json)

    def _is_ip(self, input_ip_address):
        """
        Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """
        ip_address_input = input_ip_address
        try:
            ipaddress.ip_address(UnicodeDammit(ip_address_input).unicode_markup)
        except Exception:
            return False
        return True

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text.encode('utf-8')})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successful empty response
        if (200 <= r.status_code < 205) and (not r.text):
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, params=None, body=None, headers=None, files=None, method="get", large_file=False):
        # **kwargs can be any additional parameters that requests.request accepts

        # ---------- caching code starts ---------------------------------------------------------------------

        cache = None
        cache_key = None
        call = self.get_action_identifier()
        if self._reputation_cache_length and self._reputation_cache_interval and call.endswith("_reputation"):
            expiration_interval = self._reputation_cache_interval
            cache_size = int(float(self._reputation_cache_length))
            # if saved cached data, retrieve cache otherwise create empty cache
            saved_state = self.get_state() or {}
            saved_cache = saved_state.get('vt_cache_data')
            cache = datacache(expiration_interval, cache_size, saved_cache)

            # expire old cache data and search ioc in cache
            call = self.get_action_identifier()
            if call == "url_reputation":
                tmp_value = endpoint[5:].encode(encoding='UTF-8')
                tmp_value = base64.urlsafe_b64decode(tmp_value + b'=' * (-len(tmp_value) % 4)).decode()
                cache_key = "{}:{}".format(call, "urls/" + tmp_value)
            else:
                cache_key = "{}:{}".format(call, endpoint)
            entry = cache.expire().search(cache_key)

            # save cache data to save_state
            saved_state['vt_cache_data'] = cache._cache()
            self.save_state(saved_state)

            # return entry if exists
            if entry:
                self.debug_print("Key {} retrieved from cache".format(cache_key))
                cached_status = entry[0]
                cached_data = entry[1]
                if phantom.is_fail(cached_status):
                    return RetVal(action_result.set_status(cached_status, "Cached: " + cached_data, None))
                if 'data' in cached_data:
                    cached_data['data']['results-source'] = "retrieved from cache on soar"
                # we deepcopy the data because if caller methods changes the data, it will affect the cached entry
                return RetVal(action_result.set_status(cached_status, "Entry retrieved from cache"), deepcopy(cached_data))

        # ---------- caching code ends -----------------------------------------------------------------------

        if large_file:
            url = endpoint
        else:
            url = "{}{}".format(BASE_URL, endpoint)
        self.save_progress(VIRUSTOTAL_MSG_CREATED_URL)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(error_message)), None)

        # Check rate limit
        if self._rate_limit:
            self._check_rate_limit()

        try:
            response = request_func(url, params=params, data=body, headers=headers, files=files, verify=self._verify_ssl,
                timeout=self._timeout)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting: {0}".format(error_message)), None)

        if self._rate_limit:
            self._track_rate_limit(response.headers.get('Date'))

        self.debug_print(response.url)

        if response.status_code == 429:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=response.status_code)), None)

        processed_response = self._process_response(response, action_result)

        # ---------- caching code starts ---------------------------------------------------------------------

        if cache and cache_key:
            # reform processed_response for our use.
            cached_status = processed_response[0]
            if phantom.is_fail(cached_status):
                cached_data = action_result.get_message()
            else:
                cached_data = processed_response[1]
                if isinstance(cached_data, dict) and 'data' in cached_data:
                    cached_data['data']['results-source'] = "new from virustotal"

            # expire old cache data and add ioc results to cache, then trim cache to size
            # cache size is trimmed only when adding new cache entry
            cache.expire().add(cache_key, (cached_status, cached_data)).trim()
            self.debug_print("Key {} saved to cache".format(cache_key))

            # save cache data to save_state
            saved_state['vt_cache_data'] = cache._cache()
            self.save_state(saved_state)

            if phantom.is_fail(cached_status):
                return RetVal(action_result.set_status(cached_status, cached_data), None)
            else:
                # we deepcopy the data because if caller methods changes the data, it will affect the cached entry
                return RetVal(action_result.set_status(cached_status, "Entry saved to cache"), deepcopy(cached_data))

        # ---------- caching code ends -----------------------------------------------------------------------

        return processed_response

    def _check_rate_limit(self, count=1):
        """ Check to see if the rate limit is within the "4 requests per minute". Wait and check again if the request is too soon.

        Returns:
            boolean: True, when the rate limitation is not greater than or equal to the allocated amount
        """
        self.debug_print('Checking rate limit')

        state = self.load_state()
        if not state:
            state = {}
        if not state.get('rate_limit_timestamps'):
            state['rate_limit_timestamps'] = []
            self.save_state(state)
            return True

        # Cleanup existing timestamp list to only have the timestamps within the last 60 seconds
        timestamps = state['rate_limit_timestamps']
        current_time = int(time.time())
        for timestamp in timestamps:
            time_diff = current_time - timestamp
            if time_diff > 60:
                timestamps.remove(timestamp)

        # Save new cleaned list
        state['rate_limit_timestamps'] = timestamps
        self.save_state(state)

        # If there are too many within the last minute, we will wait the min_time_diff and try again
        if len(timestamps) >= 4:
            wait_time = 61 - (current_time - min(t for t in timestamps))

            self.send_progress('Rate limit check #{0}. '
                               'Waiting {1} seconds for rate limitation to pass and will try again.'.format(count, wait_time))
            try:
                time.sleep(wait_time)
            except Exception as e:
                return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
            # Use recursive call to try again
            return self._check_rate_limit(count + 1)

        return True

    def _track_rate_limit(self, timestamp):
        """ Track timestamp of VirusTotal requests to stay within rate limitations

        Args:
            timestamp (str): Timestamp from the last requests call (e.g., 'Tue, 12 Jun 2018 16:39:37 GMT')

        Returns:
            boolean: True
        """
        self.debug_print('Tracking rate limit')

        if not timestamp:
            epoch = int(time.time())
        else:
            epoch = int(calendar.timegm(time.strptime(timestamp, '%a, %d %b %Y %H:%M:%S GMT')))

        state = self.load_state()
        timestamps = state.get('rate_limit_timestamps', [])
        timestamps.append(epoch)

        state['rate_limit_timestamps'] = timestamps
        self.save_state(state)

        return True

    def _save_file_to_vault(self, action_result, response, file_hash):

        # Create a tmp directory on the vault partition

        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/vault/tmp'

        local_dir = temp_dir + '/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder {0}.".format(temp_dir), e)

        file_path = "{0}/{1}".format(local_dir, file_hash)

        # open and download the file
        with open(file_path, 'wb') as f:
            f.write(response.content)

        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if (not file_ext):
                    file_ext = extension

        file_name = '{}{}'.format(file_hash, file_ext)

        # move the file to the vault
        status, vault_ret_message, vault_id = ph_rules.vault_add(file_location=file_path, container=self.get_container_id(),
                                                                 file_name=file_name, metadata={'contains': contains})

        curr_data = {}

        if status:
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_id
            curr_data[phantom.APP_JSON_NAME] = file_name
            if (contains):
                curr_data['file_type'] = ','.join(contains)
            action_result.add_data(curr_data)
            action_result.update_summary(curr_data)
            action_result.set_status(phantom.APP_SUCCESS, "File successfully retrieved and added to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_message)

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _handle_test_connectivity(self, param):

        self.save_progress(VIRUSTOTAL_MSG_CONNECTIVITY)

        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result, FILE_UPLOAD_URL_ENDPOINT, headers=self._headers)
        if phantom.is_fail(ret_val):
            self.save_progress(VIRUSTOTAL_ERROR_CONNECTIVITY_TEST)
            return self.virustotalv3_action_result.get_status()

        if 'data' in json_resp:
            self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS, VIRUSTOTAL_SUCC_CONNECTIVITY_TEST)
        else:
            self.virustotalv3_action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_CONNECTIVITY_TEST)

        self.save_progress(self.virustotalv3_action_result.get_message())
        return self.virustotalv3_action_result.get_status()

    def _handle_domain_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        object_name = phantom.APP_JSON_DOMAIN
        query_url = DOMAIN_API_ENDPOINT.format(id=param[object_name])

        object_value = param[object_name]

        item_summary = self.virustotalv3_action_result.set_summary({})

        self.save_progress(VIRUSTOTAL_MSG_CONNECTIVITY)

        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result, query_url, headers=self._headers)
        if phantom.is_fail(ret_val):
            return ret_val

        if 'data' not in json_resp:
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                                            VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name=object_name, object_value=object_value)

        # if last_analysis_results exists, reorganize to support standard data path format of
        # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
        if json_resp['data'].get('attributes', {}).get('last_analysis_results'):
            last_analysis_results = []
            for vendor, results in json_resp['data']['attributes']['last_analysis_results'].items():
                last_analysis_results.append({"vendor": vendor, **results})
            json_resp['data']['attributes']['last_analysis_results'] = last_analysis_results

        # add the data
        self.virustotalv3_action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']

        self.virustotalv3_action_result.update_summary(item_summary)

        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS)

    def _remove_accents(self, data):

        if isinstance(data, str):
            try:
                return data.encode('utf-8', 'surrogateescape').decode('utf-8', 'replace')
            except Exception:
                return data.encode('raw_unicode_escape')
        else:
            return data

    def _decode_object(self, obj):
        if isinstance(obj, list):
            return [self._decode_object(item) for item in obj]
        if isinstance(obj, dict):
            return {key: self._decode_object(value) for key, value in obj.items()}
        return self._remove_accents(obj)

    def _handle_file_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param

        item_summary = self.virustotalv3_action_result.set_summary({})

        hash = param['hash']

        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result,
                                                FILE_REPUTATION_ENDPOINT.format(id=hash),
                                                headers=self._headers)
        if phantom.is_fail(ret_val):
            return ret_val

        # if the Virustotal server returns any invalid characters, decode them to utf-8 characters
        if isinstance(json_resp, dict):
            json_resp = self._decode_object(json_resp)

        if 'data' not in json_resp:
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                    VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='Hash', object_value=hash)

        # if last_analysis_results exists, reorganize to support standard data path format of
        # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
        if json_resp['data'].get('attributes', {}).get('last_analysis_results'):
            last_analysis_results = []
            for vendor, results in json_resp['data']['attributes']['last_analysis_results'].items():
                last_analysis_results.append({"vendor": vendor, **results})
            json_resp['data']['attributes']['last_analysis_results'] = last_analysis_results

        self.virustotalv3_action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']

        self.virustotalv3_action_result.update_summary(item_summary)

        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        file_hash = param['hash']

        query_url = "{}{}".format(BASE_URL, GET_FILE_API_ENDPOINT.format(id=file_hash))

        # Check rate limit
        if self._rate_limit:
            self._check_rate_limit()

        # Format the request with the URL and the params
        self.save_progress(VIRUSTOTAL_MSG_CREATED_URL)
        try:
            r = requests.get(query_url, headers=self._headers, verify=self._verify_ssl, timeout=self._timeout)
        except Exception as e:
            self.debug_print("_get_file", e)
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_CONNECTIVITY_ERROR, e)

        if self._rate_limit:
            self._track_rate_limit(r.headers.get('Date'))

        self.debug_print("status_code", r.status_code)

        if (r.status_code == 429):
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if (r.status_code == 403):
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_FORBIDDEN.format(code=r.status_code))

        if (r.status_code == 404):
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_NOT_FOUND.format(code=r.status_code))

        if (r.status_code != 200):
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                    VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))

        return self._save_file_to_vault(self.virustotalv3_action_result, r, file_hash)

    def _handle_ip_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        object_name = phantom.APP_JSON_IP
        query_url = IP_API_ENDPOINT.format(id=param[object_name])

        object_value = param[object_name]

        item_summary = self.virustotalv3_action_result.set_summary({})

        self.save_progress(VIRUSTOTAL_MSG_CONNECTIVITY)

        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result, query_url, headers=self._headers)
        if phantom.is_fail(ret_val):
            return ret_val

        if 'data' not in json_resp:
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                                            VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name=object_name, object_value=object_value)

        # if last_analysis_results exists, reorganize to support standard data path format of
        # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
        if json_resp['data'].get('attributes', {}).get('last_analysis_results'):
            last_analysis_results = []
            for vendor, results in json_resp['data']['attributes']['last_analysis_results'].items():
                last_analysis_results.append({"vendor": vendor, **results})
            json_resp['data']['attributes']['last_analysis_results'] = last_analysis_results

        # add the data
        self.virustotalv3_action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']

        self.virustotalv3_action_result.update_summary(item_summary)

        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        url = param['url']

        data = {'url': url}

        # API requires base64 url without padding
        url_id = base64.urlsafe_b64encode(str(data.get('url')).encode()).decode().strip("=")

        item_summary = self.virustotalv3_action_result.set_summary({})
        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result,
                            URL_REPUTATION_ENDPOINT.format(id=url_id), headers=self._headers, method="get")

        if phantom.is_fail(ret_val):
            return self.virustotalv3_action_result.set_status(ret_val, self.virustotalv3_action_result.get_message().replace(url_id, url))

        if 'data' not in json_resp:
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                    VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='URL', object_value=param['url'])

        # if last_analysis_results exists, reorganize to support standard data path format of
        # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
        if json_resp['data'].get('attributes', {}).get('last_analysis_results'):
            last_analysis_results = []
            for vendor, results in json_resp['data']['attributes']['last_analysis_results'].items():
                last_analysis_results.append({"vendor": vendor, **results})
            json_resp['data']['attributes']['last_analysis_results'] = last_analysis_results

        self.virustotalv3_action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']
        new_scan_id = 'u-{}-{}'.format(json_resp['data']['id'], response['last_submission_date'])

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']
            item_summary['scan_id'] = new_scan_id

        self.virustotalv3_action_result.update_summary(item_summary)

        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        data = {'url': param['url']}

        ret_val, wait_time = self._validate_integers(self.virustotalv3_action_result,
                            param.get('wait_time', self._wait_time), 'wait_time', allow_zero=True)

        if phantom.is_fail(ret_val):
            return self.virustotalv3_action_result.get_status()

        url_id = base64.urlsafe_b64encode(str(data.get('url')).encode()).decode().strip("=")
        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result,
                            URL_REPUTATION_ENDPOINT.format(id=url_id), headers=self._headers, method="get")
        if phantom.is_fail(ret_val):
            if json_resp:
                if json_resp['error']['code'] == 'NotFoundError' and 'Status Code: 404' in self.virustotalv3_action_result.get_message():
                    ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result,
                                        URL_API_ENDPOINT, body=data, headers=self._headers, method='post')
                    if phantom.is_fail(ret_val):
                        return ret_val

                    try:
                        scan_id = json_resp['data']['id']
                    except KeyError:
                        return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, 'Malformed response object, missing scan_id.')
                    return self._poll_for_result(self.virustotalv3_action_result, scan_id, self._poll_interval, wait_time)

            return self.virustotalv3_action_result.get_status()

        if 'data' not in json_resp:
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                    VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='URL', object_value=param['url'])

        # if last_analysis_results exists, reorganize to support standard data path format of
        # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
        if json_resp['data'].get('attributes', {}).get('last_analysis_results'):
            last_analysis_results = []
            for vendor, results in json_resp['data']['attributes']['last_analysis_results'].items():
                last_analysis_results.append({"vendor": vendor, **results})
            json_resp['data']['attributes']['last_analysis_results'] = last_analysis_results

        item_summary = self.virustotalv3_action_result.set_summary({})
        # add the data
        self.virustotalv3_action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        new_scan_id = 'u-{}-{}'.format(json_resp['data']['id'], response['last_submission_date'])
        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']
            item_summary['scan_id'] = new_scan_id

        self.virustotalv3_action_result.update_summary(item_summary)

        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        ret_val, wait_time = self._validate_integers(self.virustotalv3_action_result,
        param.get('wait_time', self._wait_time), 'wait_time', allow_zero=True)

        if phantom.is_fail(ret_val):
            return self.virustotalv3_action_result.get_status()

        vault_id = param['vault_id']

        try:
            _, _, file_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            if not file_info:
                return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, "Could not retrieve vault file")
            file_info = list(file_info)[0]

            file_path = file_info['path']
            file_name = file_info['name']
            file_size = file_info['size']
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            if VIRUSTOTAL_EXPECTED_ERROR_MSG in error_message:
                return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                        "Unable to retrieve file from vault. Invalid vault_id.")
            else:
                return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                        "Unable to retrieve file from vault: {0}".format(error_message))

        file_hash = file_info['metadata']['sha256']

        # check if report already exists
        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result,
                            FILE_REPUTATION_ENDPOINT.format(id=file_hash), headers=self._headers)

        if phantom.is_fail(ret_val):
            if json_resp:
                # Not found on server, detonate now
                if json_resp['error']['code'] == 'NotFoundError' and 'Status Code: 404' in self.virustotalv3_action_result.get_message():
                    try:
                        files = [('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))]
                    except Exception as e:
                        error_message = self._get_error_message_from_exception(e)
                        return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                                                        'Error occurred while reading file. {}'.format(error_message))

                    # Convert file_size in bytes to MB
                    if (file_size / 1000000) > 32:
                        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result,
                                            FILE_UPLOAD_URL_ENDPOINT, headers=self._headers)
                        if phantom.is_fail(ret_val):
                            return ret_val

                        try:
                            upload_url = json_resp['data']
                        except KeyError:
                            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, "Couldn't fetch URL for uploading file")

                        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result, upload_url, headers=self._headers,
                            files=files, method='post', large_file=True)

                    else:
                        ret_val, json_resp = self._make_rest_call(self.virustotalv3_action_result, FILE_REPORT_ENDPOINT,
                            headers=self._headers, files=files, method='post')

                    if phantom.is_fail(ret_val):
                        return ret_val

                    try:
                        scan_id = json_resp['data']['id']
                    except KeyError:
                        return self.virustotalv3_action_result.set_status(phantom.APP_ERROR, 'Malformed response object, missing scan_id.')

                    return self._poll_for_result(self.virustotalv3_action_result, scan_id, self._poll_interval, wait_time)

            return self.virustotalv3_action_result.get_status()
        else:
            # if the Virustotal server returns any invalid characters, decode them to utf-8 characters
            if isinstance(json_resp, dict):
                json_resp = self._decode_object(json_resp)

        if 'data' not in json_resp:
            return self.virustotalv3_action_result.set_status(phantom.APP_ERROR,
                    VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='Hash', object_value=file_hash)

        # if last_analysis_results exists, reorganize to support standard data path format of
        # data.*.attributes.last_analysis_results.*.vendor since vendors are always changing
        if json_resp['data'].get('attributes', {}).get('last_analysis_results'):
            last_analysis_results = []
            for vendor, results in json_resp['data']['attributes']['last_analysis_results'].items():
                last_analysis_results.append({"vendor": vendor, **results})
            json_resp['data']['attributes']['last_analysis_results'] = last_analysis_results

        item_summary = self.virustotalv3_action_result.set_summary({})
        # add the data
        self.virustotalv3_action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']
        new_scan_id = '{}:{}'.format(response['md5'], response['last_submission_date'])
        new_scan_id = base64.b64encode(new_scan_id.encode()).decode()
        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']
            item_summary['scan_id'] = new_scan_id

        self.virustotalv3_action_result.update_summary(item_summary)

        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        scan_id = param['scan_id']

        ret_val, wait_time = self._validate_integers(self.virustotalv3_action_result,
                                                    param.get('wait_time', self._wait_time),
                                                    'wait_time', allow_zero=True)

        if phantom.is_fail(ret_val):
            return self.virustotalv3_action_result.get_status()

        self.save_progress("Polling for results")
        return self._poll_for_result(self.virustotalv3_action_result, scan_id, self._poll_interval, wait_time)

    # ---------- caching code starts ---------------------------------------------------------------------

    def _handle_clear_cache(self):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        saved_state = self.get_state() or {}
        if 'vt_cache_data' in saved_state:
            del saved_state['vt_cache_data']
            self.save_state(saved_state)

        self.virustotalv3_action_result.update_summary({"status": "success"})
        self.virustotalv3_action_result.add_data({"status": "success"})
        self.debug_print(self.virustotalv3_action_result.get_summary())
        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS, "cache cleared")

    def _handle_get_cached_entries(self):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        saved_state = self.get_state() or {}

        # if saved cached data, retrieve cache otherwise create empty cache
        expiration_interval = self._reputation_cache_interval
        saved_cache = saved_state.get('vt_cache_data')
        cache = datacache(expiration_interval, 0, saved_cache)

        # expire old cache data
        ret_val = cache.expire()
        if isinstance(ret_val, str):
            return RetVal(self.virustotalv3_action_result.set_status(phantom.APP_ERROR, ret_val), None)

        # save cache data to save_state
        saved_state['vt_cache_data'] = cache._cache()
        self.save_state(saved_state)

        entries = cache.items()
        data = sorted( [
            {
                'key': x[0],
                'date_added': datetime.datetime.utcfromtimestamp(x[2]).isoformat(),
                'date_expires': datetime.datetime.utcfromtimestamp(x[2] + self._reputation_cache_interval).isoformat(),
                'seconds_left': int(x[2] + self._reputation_cache_interval - time.time())
            }
            for x in entries
        ], key=lambda x: x['key'])

        self.virustotalv3_action_result.update_summary({
            "count": len(data),
            "expiration_interval": self._reputation_cache_interval,
            "max_cache_length": self._reputation_cache_length
        })
        self.virustotalv3_action_result.update_data(data)
        self.debug_print(self.virustotalv3_action_result.get_summary())
        return self.virustotalv3_action_result.set_status(phantom.APP_SUCCESS, f'count: {len(data)}')

    # ---------- caching code ends -----------------------------------------------------------------------

    def _poll_for_result(self, action_result, scan_id, poll_interval, wait_time):

        attempt = 1

        endpoint = ANALYSES_ENDPOINT.format(id=scan_id)
        try:
            time.sleep(wait_time)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
        # Since we sleep 1 minute between each poll, the poll_interval is
        # equal to the number of attempts
        poll_attempts = poll_interval
        while attempt <= poll_attempts:
            self.save_progress("Polling attempt {0} of {1}".format(attempt, poll_attempts))
            ret_val, json_resp = self._make_rest_call(action_result, endpoint, headers=self._headers, method="get")
            if phantom.is_fail(ret_val):
                return ret_val

            if isinstance(json_resp, dict):
                json_resp = self._decode_object(json_resp)

            self.debug_print(json_resp)
            if 'data' in json_resp and json_resp.get('data', {}).get('attributes', {}).get('results'):
                action_result.add_data(json_resp)

                response = json_resp['data']['attributes']
                action_result.update_summary({
                    'scan_id': scan_id,
                    'harmless': response['stats']['harmless'],
                    'malicious': response['stats']['malicious'],
                    'suspicious': response['stats']['suspicious'],
                    'undetected': response['stats']['undetected']
                })

                return action_result.set_status(phantom.APP_SUCCESS)

            attempt += 1
            time.sleep(60)

        action_result.update_summary({'scan_id': scan_id})
        return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_MAX_POLLS_REACHED)

    def handle_action(self, param):

        result = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        self.virustotalv3_action_result = self.add_action_result(ActionResult(dict(param)))

        if action_id == 'test_connectivity':
            result = self._handle_test_connectivity(param)

        elif action_id == 'domain_reputation':
            result = self._handle_domain_reputation(param)

        elif action_id == 'file_reputation':
            result = self._handle_file_reputation(param)

        elif action_id == 'get_file':
            result = self._handle_get_file(param)

        elif action_id == 'ip_reputation':
            result = self._handle_ip_reputation(param)

        elif action_id == 'url_reputation':
            result = self._handle_url_reputation(param)

        elif action_id == 'detonate_url':
            result = self._handle_detonate_url(param)

        elif action_id == 'detonate_file':
            result = self._handle_detonate_file(param)

        elif action_id == 'get_report':
            result = self._handle_get_report(param)

        elif action_id == 'clear_cache':
            result = self._handle_clear_cache()

        elif action_id == 'get_cached_entries':
            result = self._handle_get_cached_entries()

        self.virustotalv3_action_result._ActionResult__data = json.loads(json.dumps(
            self.virustotalv3_action_result._ActionResult__data).replace('\\u0000', '\\\\u0000'))

        # ---------- caching code starts ---------------------------------------------------------------------

        data = self.virustotalv3_action_result.get_data()
        summary = self.virustotalv3_action_result.get_summary()
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and 'results-source' in data[0]:
            summary['source'] = data[0].get('results-source')
            del data[0]['results-source']

        # ---------- caching code ends -----------------------------------------------------------------------

        return result

    def _initialize_error(self, msg, exception=None):
        if self.get_action_identifier() == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            self.save_progress(msg)
            self.save_progress(self._get_error_message_from_exception(exception))
            self.set_status(phantom.APP_ERROR, "Test Connectivity Failed")
        else:
            self.set_status(phantom.APP_ERROR, msg, exception)
        return phantom.APP_ERROR

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        if self._state is None:
            self._state = dict()

        self.set_validator('ipv6', self._is_ip)

        # get the asset config
        try:
            config = self.get_config()
        except Exception:
            return phantom.APP_ERROR
        self._apikey = config[VIRUSTOTAL_JSON_APIKEY]
        self._verify_ssl = True

        # ---------- caching code starts ---------------------------------------------------------------------

        if config.get(VIRUSTOTAL_JSON_ENABLE_REPUTATION_CHECK):
            cache_interval = config.get(VIRUSTOTAL_JSON_CACHE_EXPIRATION_INTERVAL, DEFAULT_CACHE_INTERVAL)
            if (not isinstance(cache_interval, float) and not isinstance(cache_interval, int)) or cache_interval < 0:
                cache_interval = 0
        else:
            cache_interval = 0

        # cache is disabled if expiration interval is not > 0
        self._reputation_cache_interval = cache_interval

        # cache size is trimmed only when adding new cache entry
        self._reputation_cache_length = config.get(VIRUSTOTAL_JSON_CACHE_EXPIRATION_LENGTH, DEFAULT_CACHE_SIZE)

        # if cache is disabled, delete any cached data
        # cache size can be significant and can affect execution time, delete cache if not used
        if not self._reputation_cache_interval and 'vt_cache_data' in self._state:
            del self._state['vt_cache_data']
            self.save_state(self._state)

        # ---------- caching code ends -----------------------------------------------------------------------

        ret_val, self._timeout = self._validate_integers(self, config.get(VIRUSTOTAL_JSON_TIMEOUT, DEFAULT_TIMEOUT), VIRUSTOTAL_JSON_TIMEOUT)
        if phantom.is_fail(ret_val):
            return self.get_status()

        self._headers = {'x-apikey': self._apikey}

        try:
            self._rate_limit = config.get(VIRUSTOTAL_JSON_RATE_LIMIT, False)
        except KeyError as ke:
            return self._initialize_error(
                "Rate Limit asset setting not configured! Please validate asset configuration and save",
                Exception('KeyError: {0}'.format(ke))
            )

        ret_val, self._poll_interval = self._validate_integers(self, config.get("poll_interval", 5), "poll_interval")
        if phantom.is_fail(ret_val):
            return self.get_status()

        ret_val, self._wait_time = self._validate_integers(self, config.get("waiting_time", 0), "waiting_time", allow_zero=True)
        if phantom.is_fail(ret_val):
            return self.get_status()

        return phantom.APP_SUCCESS

    def finalize(self):

        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VirustotalV3Connector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
