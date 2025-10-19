# File: virustotalv3_DataCache.py
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
import time


class DataCache:
    def __init__(self, interval=None, length=None, cache=None):
        self.set_expiration_interval(interval)
        self.set_cache_length(length)
        self._set_cache(cache)

    def expire(self, interval=None):
        if interval == 0:
            # asked to purge cache
            self._set_cache()
            return
        if interval is None:
            interval = self.expiration_interval()
        current_time = time.time()
        for key, value, timestamp in self.items():
            try:
                if timestamp + interval <= current_time:
                    self.delete(key)
            except Exception:
                return "Invalid timestamp value found. Please run clear cache action first and try again."
        return self

    def set_expiration_interval(self, interval):
        if not interval or interval < 0:
            interval = 60
        self._expiration_interval = interval
        return self

    def set_cache_length(self, length):
        if not length or length < 0:
            # no limit to cache size if length == 0
            length = 0
        self._cache_length = int(length)
        return self

    def expiration_interval(self):
        return self._expiration_interval

    ################################################################################
    # data_store implementation aware methods
    ################################################################################

    def add(self, key, value):
        self._datastore[key] = {"value": value, "timestamp": time.time()}
        return self

    def search(self, key):
        return self._datastore.get(key, {}).get("value")

    def delete(self, key):
        self._datastore.pop(key, None)
        return self

    def items(self):
        return [(key, data["value"], data["timestamp"]) for key, data in self._datastore.items()]

    # implemented here for speed, well, for a given value of speed
    def trim(self, length=None):
        if length is None:
            length = int(self._cache_length)

        # disable trimming if length == 0:
        if length == 0:
            return self

        # if cache size is less than length, nothing to do
        cache = self._datastore.items()
        if len(cache) <= length:
            return self

        # sort cache by timestamp to get the oldest entries and trim
        cache = sorted(cache, key=lambda x: x[1]["timestamp"])
        cache = cache[-length:]
        self._datastore = dict(cache)
        return self

    def _set_cache(self, data=None):
        if isinstance(data, dict):
            self._datastore = data
        else:
            self._datastore = dict()
        return self

    def _cache(self):
        return self._datastore
