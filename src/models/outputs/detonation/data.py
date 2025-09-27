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
from soar_sdk.action_results import ActionOutput, OutputField
from typing import Optional
from ..file_reputation.analysis import FileAnalysisResults, FileAnalysisStats


class ScanLinks(ActionOutput):
    item: Optional[str] = OutputField(
        example_values=[
            "https://www.virustotal.com/api/v3/files/917c72a2684d1573ea363b2f91e3aedcef1996fc34668ba9d369ad9123d1380f"
        ]
    )
    self: Optional[str] = OutputField(
        example_values=[
            "https://www.virustotal.com/api/v3/analyses/ZDhhNjY5NmU2NDJlYzUyMDUwMmEwNWE0YWRkOGMxNzk6MTY3ODY4OTQ5Mg=="
        ]
    )


class FileInfo(ActionOutput):
    md5: Optional[str] = OutputField(
        cef_types=["md5"], example_values=["299999999992c49c91a0206ee7a8c00e659"]
    )
    name: Optional[str] = OutputField(example_values=["update_cr.py"])
    sha1: Optional[str] = OutputField(
        cef_types=["sha1"], example_values=["9999999999142292710254cde97df84e46dfe33a"]
    )
    sha256: Optional[str] = OutputField(
        cef_types=["sha256"],
        example_values=[
            "e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"
        ],
    )
    size: Optional[int] = OutputField(example_values=[6285])

class URLInfo(ActionOutput):
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"
        ],
    )
    url: str = OutputField(example_values=["https://www.virustotal.com/api/v3/domains/test.com"])


class MetaOutput(ActionOutput):
    file_info: Optional[FileInfo]
    url_info: Optional[URLInfo]


class PollingDataAttributes(ActionOutput):
    date: int = OutputField(cef_types=["timestamp"], example_values=[1613651763])
    results: Optional[FileAnalysisResults]
    stats: FileAnalysisStats
    status: str = OutputField(example_values=["completed"])


class PollingData(ActionOutput):
    attributes: PollingDataAttributes
    id: str = OutputField(
        cef_types=["virustotal scan id"],
        example_values=["MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw=="],
    )
    links: ScanLinks
    type: str
    meta: Optional[MetaOutput]
