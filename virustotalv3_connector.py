# File: virustotalv3_connector.py
#
# Copyright (c) 2021-2022 Splunk Inc.
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
import ipaddress
import json
# Other imports used by this connector
import os
import re
import shutil
import sys
import time
import uuid

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

        self._python_version = None
        self._state = None
        self._apikey = None
        self._rate_limit = None
        self._verify_ssl = None
        self._poll_interval = None
        self._wait_time = None
        self._headers = dict()

    def _handle_py_ver_compat_for_input_str(self, input_str):

        """
        This method returns the encoded|original string based on the Python version.

        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str -
        Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except Exception:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = VIRUSTOTAL_UNKNOWN_ERROR_CODE_MSG
        error_msg = VIRUSTOTAL_UNKNOWN_ERROR_MSG
        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = VIRUSTOTAL_UNKNOWN_ERROR_CODE_MSG
                    error_msg = e.args[0]
        except Exception:
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = VIRUSTOTAL_TYPE_ERROR_MSG
        except Exception:
            error_msg = VIRUSTOTAL_UNKNOWN_ERROR_MSG

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

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

            error_text = soup.text.encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        error_text = self._handle_py_ver_compat_for_input_str(error_text)

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
                'message': self._handle_py_ver_compat_for_input_str(error_info.get('code')),
                'detail': self._handle_py_ver_compat_for_input_str(error_info.get('message'))
            }
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   "Error from server, Status Code: {0} data returned: {1}".format
                                                   (r.status_code, error_details)), resp_json)
        else:
            message = self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}'))
            return RetVal( action_result.set_status(phantom.APP_ERROR,
                                                    "Error from server, Status Code: {0} data returned: {1}".format
                                                    (r.status_code, message)), resp_json)

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
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, params=None, body=None, headers=None, files=None, method="get"):
        # **kwargs can be any additional parameters that requests.request accepts

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
                timeout=DEFAULT_TIMEOUT)
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

        return self._process_response(response, action_result)

    def _check_rate_limit(self, count=1):
        """ Check to see if the rate limit is within the "4 requests per minute". Wait and check again if the request is too soon.

        Returns:
            boolean: True, when the rate limitation is not greater than or equal to the allocated amount
        """
        self.debug_print('Checking rate limit')

        state = self.load_state()
        if not state or not state.get('rate_limit_timestamps'):
            self.save_state({'rate_limit_timestamps': []})
            return True

        # Cleanup existing timestamp list to only have the timestamps within the last 60 seconds
        timestamps = state['rate_limit_timestamps']
        current_time = int(time.time())
        for timestamp in timestamps:
            time_diff = current_time - timestamp
            if time_diff > 60:
                timestamps.remove(timestamp)

        # Save new cleaned list
        self.save_state({'rate_limit_timestamps': timestamps})

        # If there are too many within the last minute, we will wait the min_time_diff and try again
        if len(timestamps) >= 4:
            wait_time = 61 - (current_time - min(t for t in timestamps))

            self.send_progress('Rate limit check #{0}. '
                               'Waiting {1} seconds for rate limitation to pass and will try again.'.format(count, wait_time))
            time.sleep(wait_time)
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

        self.save_state({'rate_limit_timestamps': timestamps})

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

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(VIRUSTOTAL_MSG_CONNECTING)

        ret_val, json_resp = self._make_rest_call(action_result, FILE_TEST_CONN_ENDPOINT, headers=self._headers)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_MSG_CHECK_APIKEY)

        if 'data' in json_resp:
            action_result.set_status(phantom.APP_SUCCESS, VIRUSTOTAL_SUCC_CONNECTIVITY_TEST)
        else:
            action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_CONNECTIVITY_TEST)

        self.save_progress(action_result.get_message())
        return action_result.get_status()

    def _handle_domain_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        object_name = phantom.APP_JSON_DOMAIN
        query_url = DOMAIN_API_ENDPOINT.format(id=param[object_name])

        action_result = self.add_action_result(ActionResult(dict(param)))

        object_value = param[object_name]

        item_summary = action_result.set_summary({})

        self.save_progress(VIRUSTOTAL_MSG_CONNECTING)

        ret_val, json_resp = self._make_rest_call(action_result, query_url, headers=self._headers)
        if phantom.is_fail(ret_val):
            return ret_val

        if 'data' not in json_resp:
            return action_result.set_status(phantom.APP_ERROR,
                                            VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name=object_name, object_value=object_value)

        # add the data
        action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']

        action_result.update_summary(item_summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        item_summary = action_result.set_summary({})

        hash = param['hash']

        ret_val, json_resp = self._make_rest_call(action_result, FILE_REPUTATION_ENDPOINT.format(id=hash), headers=self._headers)
        if phantom.is_fail(ret_val):
            return ret_val

        if 'data' not in json_resp:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='Hash', object_value=hash)

        action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']

        action_result.update_summary(item_summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param['hash']

        query_url = "{}{}".format(BASE_URL, GET_FILE_API_ENDPOINT.format(id=file_hash))

        # Check rate limit
        if self._rate_limit:
            self._check_rate_limit()

        # Format the request with the URL and the params
        self.save_progress(VIRUSTOTAL_MSG_CREATED_URL)
        try:
            r = requests.get(query_url, headers=self._headers, verify=self._verify_ssl, timeout=DEFAULT_TIMEOUT)
        except Exception as e:
            self.debug_print("_get_file", e)
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_CONNECTION_ERROR, e)

        if self._rate_limit:
            self._track_rate_limit(r.headers.get('Date'))

        self.debug_print("status_code", r.status_code)

        if (r.status_code == 429):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if (r.status_code == 403):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_FORBIDDEN.format(code=r.status_code))

        if (r.status_code == 404):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_NOT_FOUND.format(code=r.status_code))

        if (r.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))

        return self._save_file_to_vault(action_result, r, file_hash)

    def _handle_ip_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        object_name = phantom.APP_JSON_IP
        query_url = IP_API_ENDPOINT.format(id=param[object_name])

        object_value = param[object_name]

        item_summary = action_result.set_summary({})

        self.save_progress(VIRUSTOTAL_MSG_CONNECTING)

        ret_val, json_resp = self._make_rest_call(action_result, query_url, headers=self._headers)
        if phantom.is_fail(ret_val):
            return ret_val

        if 'data' not in json_resp:
            return action_result.set_status(phantom.APP_ERROR,
                                            VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name=object_name, object_value=object_value)

        # add the data
        action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']

        action_result.update_summary(item_summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']

        data = {'url': url}

        # API requires base64 url without padding
        url_id = base64.urlsafe_b64encode(str(data.get('url')).encode()).decode().strip("=")

        item_summary = action_result.set_summary({})
        ret_val, json_resp = self._make_rest_call(action_result, URL_REPUTATION_ENDPOINT.format(id=url_id), headers=self._headers, method="get")

        if phantom.is_fail(ret_val):
            return ret_val

        if 'data' not in json_resp:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='URL', object_value=param['url'])

        action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']
        new_scan_id = 'u-{}-{}'.format(json_resp['data']['id'], response['last_submission_date'])

        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']
            item_summary['scan_id'] = new_scan_id

        action_result.update_summary(item_summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(param))

        data = {'url': param['url']}

        ret_val, wait_time = self._validate_integers(action_result, param.get('wait_time', self._wait_time), 'wait_time', allow_zero=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        url_id = base64.urlsafe_b64encode(str(data.get('url')).encode()).decode().strip("=")
        ret_val, json_resp = self._make_rest_call(action_result, URL_REPUTATION_ENDPOINT.format(id=url_id), headers=self._headers, method="get")
        if phantom.is_fail(ret_val):
            if json_resp:
                if json_resp['error']['code'] == 'NotFoundError' and 'Status Code: 404' in action_result.get_message():
                    ret_val, json_resp = self._make_rest_call(action_result, URL_API_ENDPOINT, body=data, headers=self._headers, method='post')
                    if phantom.is_fail(ret_val):
                        return ret_val

                    try:
                        scan_id = json_resp['data']['id']
                    except KeyError:
                        return action_result.set_status(phantom.APP_ERROR, 'Malformed response object, missing scan_id.')
                    return self._poll_for_result(action_result, scan_id, self._poll_interval, wait_time)

            return action_result.get_status()

        if 'data' not in json_resp:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='URL', object_value=param['url'])

        item_summary = action_result.set_summary({})
        # add the data
        action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']

        new_scan_id = 'u-{}-{}'.format(json_resp['data']['id'], response['last_submission_date'])
        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']
            item_summary['scan_id'] = new_scan_id

        action_result.update_summary(item_summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(param))

        ret_val, wait_time = self._validate_integers(action_result, param.get('wait_time', self._wait_time), 'wait_time', allow_zero=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vault_id = param['vault_id']

        try:
            _, _, file_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            if not file_info:
                return action_result.set_status(phantom.APP_ERROR, "Could not retrieve vault file")
            file_info = list(file_info)[0]

            file_path = file_info['path']
            file_name = file_info['name']
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            if VIRUSTOTAL_EXPECTED_ERROR_MSG in error_message:
                return action_result.set_status(phantom.APP_ERROR, "Unable to retrieve file from vault. Invalid vault_id.")
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unable to retrieve file from vault: {0}".format(error_message))

        file_hash = file_info['metadata']['sha256']

        # check if report already exists
        ret_val, json_resp = self._make_rest_call(action_result, FILE_REPUTATION_ENDPOINT.format(id=file_hash), headers=self._headers)
        if phantom.is_fail(ret_val):
            if json_resp:
                # Not found on server, detonate now
                if json_resp['error']['code'] == 'NotFoundError' and 'Status Code: 404' in action_result.get_message():
                    try:
                        files = [('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))]
                    except Exception as e:
                        error_message = self._get_error_message_from_exception(e)
                        return action_result.set_status(phantom.APP_ERROR,
                                                        'Error occurred while reading file. {}'.format(error_message))

                    ret_val, json_resp = self._make_rest_call(action_result, FILE_REPORT_ENDPOINT,
                                                              headers=self._headers, files=files, method='post')
                    if phantom.is_fail(ret_val):
                        return ret_val

                    try:
                        scan_id = json_resp['data']['id']
                    except KeyError:
                        return action_result.set_status(phantom.APP_ERROR, 'Malformed response object, missing scan_id.')

                    return self._poll_for_result(action_result, scan_id, self._poll_interval, wait_time)

            return action_result.get_status()

        if 'data' not in json_resp:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_MSG_OBJECT_QUERIED, object_name='Hash', object_value=file_hash)

        item_summary = action_result.set_summary({})
        # add the data
        action_result.add_data(json_resp['data'])

        response = json_resp['data']['attributes']
        new_scan_id = '{}:{}'.format(response['md5'], response['last_submission_date'])
        new_scan_id = base64.b64encode(new_scan_id.encode()).decode()
        if 'last_analysis_stats' in response:
            item_summary['harmless'] = response['last_analysis_stats']['harmless']
            item_summary['malicious'] = response['last_analysis_stats']['malicious']
            item_summary['suspicious'] = response['last_analysis_stats']['suspicious']
            item_summary['undetected'] = response['last_analysis_stats']['undetected']
            item_summary['scan_id'] = new_scan_id

        action_result.update_summary(item_summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        scan_id = param['scan_id']

        ret_val, wait_time = self._validate_integers(action_result, param.get('wait_time', self._wait_time), 'wait_time', allow_zero=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return self._poll_for_result(action_result, scan_id, self._poll_interval, wait_time)

    def _poll_for_result(self, action_result, scan_id, poll_interval, wait_time):

        attempt = 1

        endpoint = ANALYSES_ENDPOINT.format(id=scan_id)
        time.sleep(wait_time)
        # Since we sleep 1 minute between each poll, the poll_interval is
        # equal to the number of attempts
        poll_attempts = poll_interval
        while attempt <= poll_attempts:
            self.save_progress("Polling attempt {0} of {1}".format(attempt, poll_attempts))
            ret_val, json_resp = self._make_rest_call(action_result, endpoint, headers=self._headers, method="get")
            if phantom.is_fail(ret_val):
                return ret_val
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
        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            return self.set_status(phantom.APP_ERROR,
                                   "Error occurred while getting the Phantom server's Python major version.")

        # get the asset config
        try:
            config = self.get_config()
        except Exception:
            return phantom.APP_ERROR
        self._apikey = config[VIRUSTOTAL_JSON_APIKEY]
        self._verify_ssl = True

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
