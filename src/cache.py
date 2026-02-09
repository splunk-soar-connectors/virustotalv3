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
import time
from typing import Optional
import math


class DataCache:
    def __init__(self, interval: int, length: int, cache: Optional[dict] = None):
        self.interval = interval
        self.length = int(length) if length >= 0 else math.inf
        self.cache = cache or {}
        self._oldest_key = ""

    def expire(self) -> "DataCache":
        if self.interval == 0:
            self.cache = {}

        current_time = time.time()
        keys_to_delete = []
        for key, val_dict in self.cache.items():
            timestamp = val_dict["timestamp"]
            if current_time - timestamp > self.interval:
                keys_to_delete.append(key)
                continue

            # try to be a little efficent when grabbing the oldest key so we don't have to iterate over the whole cache when adding a new entry
            if self.cache[key]["timestamp"] < self.cache.get(self._oldest_key, {}).get(
                "timestamp", math.inf
            ):
                self._oldest_key = key

        for key in keys_to_delete:
            del self.cache[key]

        return self

    def search(self, key: str):
        return self.cache.get(key, {}).get("value")

    def get_oldest_key(self) -> str:
        if self._oldest_key in self.cache:
            return self._oldest_key

        for key, val_dict in self.cache.items():
            timestamp = val_dict["timestamp"]
            if timestamp < self.cache.get(self._oldest_key, {}).get(
                "timestamp", math.inf
            ):
                self._oldest_key = key

        return self._oldest_key

    def add(self, key: str, value: str):
        if len(self.cache) >= self.length:
            oldest_key = self.get_oldest_key()
            self.cache.pop(oldest_key)
        self.cache[key] = {"value": value, "timestamp": time.time()}
