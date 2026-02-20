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
from typing import Optional
from soar_sdk.action_results import ActionOutput, OutputField


class FileSandboxResult(ActionOutput):
    category: Optional[str] = OutputField(
        example_values=["malicious", "harmless", "suspicious"]
    )
    confidence: Optional[int]
    malware_classification: Optional[list[str]] = OutputField(example_values=["CLEAN"])
    malware_names: Optional[list[str]]
    sandbox_name: Optional[str]


class FileSandboxVerdicts(ActionOutput):
    Zenbox: Optional[FileSandboxResult]
    Zenbox_Linux: Optional[FileSandboxResult]
