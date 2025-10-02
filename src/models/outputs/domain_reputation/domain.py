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
from typing import Optional
from soar_sdk.action_results import ActionOutput, OutputField

from models.outputs.shared.rdap import RDAP
from models.outputs.domain_reputation.popularity import PopularityRanks
from models.outputs.shared.tls import HTTPSCertificate
from models.outputs.domain_reputation.analysis import (
    DomainAnalysisResults,
    DomainAnalysisStats,
)
from models.outputs.shared.main import TotalVotes


class DNSRecord(ActionOutput):
    type: str = OutputField(example_values=["A"])
    value: str = OutputField(example_values=["192.0.2.1"])
    ttl: int
    rname: Optional[str]
    serial: Optional[int]
    refresh: Optional[int]
    retry: Optional[int]
    expire: Optional[int]
    minimum: Optional[int]


class DomainCategories(ActionOutput):
    alphaMountain_ai: Optional[str]
    BitDefender: Optional[str]
    Xcitium_Verdict_Cloud: Optional[str]
    Sophos: Optional[str]
    Forcepoint_ThreatSeeker: Optional[str]


class DomainAttributes(ActionOutput):
    last_dns_records_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1757503155]
    )
    jarm: Optional[str] = OutputField(
        example_values=[
            "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae"  # pragma: allowlist secret
        ]
    )
    last_analysis_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1679467461]
    )
    creation_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1613635130]
    )
    last_analysis_results: DomainAnalysisResults
    total_votes: TotalVotes
    whois_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1613635130]
    )
    expiration_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1613635130]
    )
    last_modification_date: int = OutputField(
        cef_types=["timestamp"], example_values=[1613635210]
    )
    whois: Optional[str] = OutputField(
        example_values=[
            "Test data Domain Name: TEST.COM Registry Domain ID: 9999999999_DOMAIN_COM-VRSN Registrar WHOIS Server: whois.test.com Registrar URL: http://www.test.com Updated Date: 2021-02-17T07:07:07Z Creation Date: 2021-02-17T07:07:07Z Registry Expiry Date: 2022-02-17T07:07:07Z Registrar: Test Registrar, Inc. Registrar IANA ID: 9999 Registrar Abuse Contact Email:"
        ]
    )
    reputation: int
    last_dns_records: list[DNSRecord]
    last_https_certificate: Optional[HTTPSCertificate]
    tld: str = OutputField(example_values=["com"])
    last_https_certificate_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1613635210]
    )
    last_analysis_stats: DomainAnalysisStats
    registrar: Optional[str]
    categories: DomainCategories
    popularity_ranks: PopularityRanks
    last_update_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1613635210]
    )
    rdap: Optional[RDAP]
    tags: list[str]
