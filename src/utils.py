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
