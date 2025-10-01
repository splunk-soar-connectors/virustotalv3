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
from token import OP
from typing import Optional
from soar_sdk.action_results import ActionOutput, OutputField

from models.outputs.shared.main import TotalVotes
from models.outputs.ip_reputation.analysis import IPAnalysisResults, IPAnalysisStats
from models.outputs.shared.tls import HTTPSCertificate


class IPAttributes(ActionOutput):
    as_owner: Optional[str]
    asn: Optional[int]
    continent: Optional[str]
    country: Optional[str]
    jarm: Optional[str]
    last_analysis_date: int = OutputField(cef_types=["timestamp"])
    last_analysis_results: IPAnalysisResults
    last_analysis_stats: IPAnalysisStats
    last_https_certificate: Optional[HTTPSCertificate]
    last_https_certificate_date: Optional[int] = OutputField(cef_types=["timestamp"])
    last_modification_date: int = OutputField(cef_types=["timestamp"])
    network: Optional[str] = OutputField(cef_types=["ip"])
    reputation: int
    total_votes: TotalVotes
    whois: Optional[str]
    whois_date: Optional[int] = OutputField(cef_types=["timestamp"])
    tags: list[str]
