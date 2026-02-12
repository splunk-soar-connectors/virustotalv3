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
from soar_sdk.action_results import ActionOutput, OutputField
from typing import Optional

from models.outputs.url_reputation.analysis import URLAnalysisStats, URLAnalysisResult
from models.outputs.shared.main import TotalVotes


class URLCategories(ActionOutput):
    alphaMountain_ai: Optional[str]
    BitDefender: Optional[str]
    Xcitium_Verdict_Cloud: Optional[str]
    Sophos: Optional[str]
    Forcepoint_ThreatSeeker: Optional[str]


class Favicon(ActionOutput):
    dhash: str
    raw_md5: str = OutputField(cef_types=["md5"])


class URLAttributes(ActionOutput):
    categories: Optional[URLCategories]
    favicon: Optional[Favicon]
    first_submission_date: str = OutputField(cef_types=["timestamp"])
    last_analysis_date: str = OutputField(cef_types=["timestamp"])
    last_analysis_results: list[URLAnalysisResult]
    last_analysis_stats: URLAnalysisStats
    last_final_url: Optional[str]
    last_http_response_code: Optional[int]
    last_http_response_content_length: Optional[int]
    last_http_response_content_sha256: Optional[str] = OutputField(cef_types=["sha256"])
    last_modification_date: str = OutputField(cef_types=["timestamp"])
    last_submission_date: str = OutputField(cef_types=["timestamp"])
    outgoing_links: Optional[list[str]]
    redirection_chain: Optional[list[str]]
    reputation: int
    tags: Optional[list[str]]
    times_submitted: int
    title: Optional[str]
    total_votes: TotalVotes
    url: str = OutputField(cef_types=["url"])
    has_content: bool = False
