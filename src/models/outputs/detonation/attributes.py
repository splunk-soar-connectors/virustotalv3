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
from pydantic import validator
from ..file_reputation.analysis import FileAnalysisResult
from ..file_reputation.sandbox import FileSandboxVerdicts
from ..file_reputation.file import TrID
from ..file_reputation.analysis import FileAnalysisStats
from ..file_reputation.pdf_info import PDFInfo
from ..file_reputation.pe_info import PEInfo
from ..file_reputation.popular_threat_classification import PopularThreatClassification
from ..shared.main import TotalVotes
from ..shared.tls import HTTPSCertificate


class AndroguardPermissionDetail(ActionOutput):
    full_description: Optional[str] = OutputField(
        example_values=["Allows an application to create network sockets."]
    )
    permission_type: Optional[str] = OutputField(example_values=["dangerous"])
    short_description: Optional[str] = OutputField(
        example_values=["full Internet access"]
    )


class AndroidPermissionGroup(ActionOutput):
    """Represents android.permission.* permissions"""

    INTERNET: Optional[AndroguardPermissionDetail]
    WRITE_EXTERNAL_STORAGE: Optional[AndroguardPermissionDetail]
    READ_EXTERNAL_STORAGE: Optional[AndroguardPermissionDetail]
    ACCESS_NETWORK_STATE: Optional[AndroguardPermissionDetail]
    CAMERA: Optional[AndroguardPermissionDetail]
    RECORD_AUDIO: Optional[AndroguardPermissionDetail]
    ACCESS_FINE_LOCATION: Optional[AndroguardPermissionDetail]
    ACCESS_COARSE_LOCATION: Optional[AndroguardPermissionDetail]
    READ_CONTACTS: Optional[AndroguardPermissionDetail]
    WRITE_CONTACTS: Optional[AndroguardPermissionDetail]
    READ_SMS: Optional[AndroguardPermissionDetail]
    SEND_SMS: Optional[AndroguardPermissionDetail]
    CALL_PHONE: Optional[AndroguardPermissionDetail]
    READ_PHONE_STATE: Optional[AndroguardPermissionDetail]


class AndroidPermissions(ActionOutput):
    permission: Optional[AndroidPermissionGroup]


class PermissionDetails(ActionOutput):
    android: Optional[AndroidPermissions]


class RiskEntry(ActionOutput):
    key: str = OutputField(example_values=["ACTIVITY"])
    value: int = OutputField(example_values=[5])


class AndroguardRiskIndicator(ActionOutput):
    APK: Optional[list[RiskEntry]]
    PERM: Optional[list[RiskEntry]]

    @validator("APK", "PERM", pre=True)
    @classmethod
    def flatten_dict_to_list(cls, v):
        """Convert dict to list of key-value objects"""
        if isinstance(v, dict):
            return [RiskEntry(key=k, value=val) for k, val in v.items()]
        return v


class Androguard(ActionOutput):
    Activities: Optional[list[str]]
    AndroguardVersion: Optional[str] = OutputField(example_values=["3.0-dev"])
    AndroidApplication: Optional[int] = OutputField(example_values=[1])
    AndroidApplicationError: Optional[bool] = OutputField(example_values=[False])
    AndroidApplicationInfo: Optional[str] = OutputField(example_values=["APK"])
    AndroidVersionCode: Optional[str] = OutputField(example_values=["1"])
    AndroidVersionName: Optional[str] = OutputField(example_values=["1.0"])
    MinSdkVersion: Optional[str] = OutputField(example_values=["11"])
    Package: Optional[str] = OutputField(
        example_values=["com.ibm.android.analyzer.test"]
    )
    RiskIndicator: Optional[AndroguardRiskIndicator]
    TargetSdkVersion: Optional[str] = OutputField(example_values=["11"])
    VTAndroidInfo: Optional[float] = OutputField(example_values=[1.41])
    certificate: Optional[HTTPSCertificate]
    main_activity: Optional[str] = OutputField(
        example_values=["com.ibm.android.analyzer.test.xas.CAS"]
    )
    Services: Optional[list[str]]
    StringsInformation: Optional[list[str]]
    permission_details: Optional[PermissionDetails]


class Extension(ActionOutput):
    key: Optional[str] = OutputField(example_values=[".exe"])
    count: Optional[str] = OutputField(example_values=["1"])


class BundleInfo(ActionOutput):
    extensions: Optional[list[Extension]]
    file_types: Optional[list[Extension]]
    highest_datetime: Optional[str] = OutputField(
        example_values=["2019-01-03 12:33:40"]
    )
    lowest_datetime: Optional[str] = OutputField(example_values=["2019-01-03 12:33:40"])
    num_children: Optional[int] = OutputField(example_values=[1])
    type: Optional[str] = OutputField(example_values=["ZIP"])
    uncompressed_size: Optional[int] = OutputField(example_values=[481])

    @validator("extensions", "file_types", pre=True)
    @classmethod
    def flatten_dict_to_list(cls, v):
        """Convert dict to list of key-value objects"""
        if isinstance(v, dict):
            return [Extension(key=k, value=val) for k, val in v.items()]
        return v


class CrowdsourcedIdsResult(ActionOutput):
    alert_severity: Optional[str] = OutputField(example_values=["medium"])
    rule_category: Optional[str] = OutputField(
        example_values=["Potentially Bad Traffic"]
    )
    rule_id: Optional[str] = OutputField(example_values=["1:2027865"])
    rule_msg: Optional[str] = OutputField(
        example_values=["ET INFO Observed DNS Query to .cloud TLD"]
    )
    rule_raw: Optional[str] = OutputField(
        example_values=[
            'alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns.query; content:".cloud"; nocase; endswith; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027865; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2019_08_13, deployment Perimeter, former_category INFO, signature_severity Major, updated_at 2020_09_17;)'
        ]
    )
    rule_source: Optional[str] = OutputField(
        example_values=["Proofpoint Emerging Threats Open"]
    )
    rule_url: Optional[str] = OutputField(
        example_values=["https://rules.emergingthreats.net/"]
    )


class HTMLInfoAttributes(ActionOutput):
    src: Optional[str] = OutputField(example_values=["./test_html_files/list.html"])
    width: Optional[str] = OutputField(example_values=["100%"])
    height: Optional[str] = OutputField(example_values=["400px"])


class HtmlInfoIframe(ActionOutput):
    attributes: HTMLInfoAttributes


class HtmlInfoScript(ActionOutput):
    attributes: HTMLInfoAttributes


class HtmlInfo(ActionOutput):
    iframes: Optional[list[HtmlInfoIframe]]
    scripts: Optional[list[HtmlInfoScript]]


class Packers(ActionOutput):
    F_PROT: Optional[str] = OutputField(example_values=["appended, docwrite"])


class DetonateFileAttributes(ActionOutput):
    androguard: Optional[Androguard]
    authentihash: Optional[str] = OutputField(
        example_values=[
            "9999999999a601c12ac88d70736e5a5064dac716fe071ce9e3bb206d67b1b9a5",  # pragma: allowlist secret
        ]
    )
    bundle_info: Optional[BundleInfo]
    bytehero_info: Optional[str] = OutputField(example_values=["Trojan.Win32.Heur.Gen"])
    creation_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1539102614]
    )
    crowdsourced_ids_results: Optional[list[CrowdsourcedIdsResult]]
    crowdsourced_ids_stats: Optional[list[int]] = OutputField(example_values=[0])
    first_seen_itw_date: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1502111702]
    )
    first_submission_date: int = OutputField(
        cef_types=["timestamp"], example_values=[1612961082]
    )
    html_info: Optional[HtmlInfo]
    last_analysis_date: int = OutputField(
        cef_types=["timestamp"], example_values=[1613635130]
    )
    last_analysis_results: list[FileAnalysisResult]
    last_analysis_stats: FileAnalysisStats
    last_modification_date: int = OutputField(
        cef_types=["timestamp"], example_values=[1613635210]
    )
    last_submission_date: int = OutputField(
        cef_types=["timestamp"], example_values=[1613635130]
    )
    magic: Optional[str] = OutputField(
        example_values=["a python2.7\\015script text executable"]
    )
    md5: str = OutputField(
        cef_types=["md5"], example_values=["99999999992c49c91a0206ee7a8c00e659"]
    )
    meaningful_name: Optional[str] = OutputField(example_values=["update_cr.py"])
    names: list[str] = OutputField(example_values=[["update_cr.py"]])
    packers: Optional[Packers]
    pdf_info: Optional[PDFInfo]
    pe_info: Optional[PEInfo]
    popular_threat_classification: Optional[PopularThreatClassification]
    reputation: int = OutputField(example_values=[0])
    sandbox_verdicts: Optional[FileSandboxVerdicts]
    sha1: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "99999999999142292710254cde97df84e46dfe33a",  # pragma: allowlist secret
        ],
    )
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe",  # pragma: allowlist secret
        ],
    )
    signature_info: Optional[list[str]] = OutputField(example_values=["xyz"])
    size: int = OutputField(example_values=[6285])
    ssdeep: Optional[str] = OutputField(
        example_values=[
            "192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygi6OLxgUHzYu7ThPBLkv:pq7Mgg0/NdMu/1BLkv",  # pragma: allowlist secret
        ]
    )
    tags: Optional[list[str]] = OutputField(example_values=[["python"]])
    times_submitted: int = OutputField(example_values=[13])
    tlsh: Optional[str] = OutputField(
        example_values=[
            "9999999999C5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC",  # pragma: allowlist secret
        ]
    )
    total_votes: Optional[TotalVotes]
    trid: Optional[list[TrID]]
    type_description: Optional[str] = OutputField(example_values=["Python"])
    type_extension: Optional[str] = OutputField(example_values=["py"])
    type_tag: Optional[str] = OutputField(example_values=["python"])
    unique_sources: Optional[int] = OutputField(example_values=[1])
    vhash: Optional[str]
