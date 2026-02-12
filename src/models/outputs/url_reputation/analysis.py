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


class URLAnalysisResult(ActionOutput):
    category: str = OutputField(example_values=["malicious"])
    engine_name: str = OutputField(example_values=["CMC"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["Trojan.GenericKD.3275421"])
    vendor: Optional[str] = OutputField(example_values=["AutoShun, CMC"])


class URLAnalysisResults(ActionOutput):
    Acronis: Optional[URLAnalysisResult]
    SI_f33d: Optional[URLAnalysisResult] = OutputField(alias="0xSI_f33d")
    Abusix: Optional[URLAnalysisResult]
    ADMINUSLabs: Optional[URLAnalysisResult]
    Axur: Optional[URLAnalysisResult]
    ChainPatrol: Optional[URLAnalysisResult]
    Criminal_IP: Optional[URLAnalysisResult]
    AILabs_MONITORAPP: Optional[URLAnalysisResult]
    AlienVault: Optional[URLAnalysisResult]
    alphaMountain_ai: Optional[URLAnalysisResult]
    AlphaSOC: Optional[URLAnalysisResult]
    Antiy_AVL: Optional[URLAnalysisResult]
    ArcSight_Threat_Intelligence: Optional[URLAnalysisResult]
    AutoShun: Optional[URLAnalysisResult]
    benkow_cc: Optional[URLAnalysisResult]
    Bfore_Ai_PreCrime: Optional[URLAnalysisResult]
    BitDefender: Optional[URLAnalysisResult]
    Bkav: Optional[URLAnalysisResult]
    Blueliv: Optional[URLAnalysisResult]
    Certego: Optional[URLAnalysisResult]
    Chong_Lua_Dao: Optional[URLAnalysisResult]
    CINS_Army: Optional[URLAnalysisResult]
    Cluster25: Optional[URLAnalysisResult]
    CRDF: Optional[URLAnalysisResult]
    CSIS_Security_Group: Optional[URLAnalysisResult]
    Snort_IP_sample_list: Optional[URLAnalysisResult]
    CMC_Threat_Intelligence: Optional[URLAnalysisResult]
    Cyan: Optional[URLAnalysisResult]
    Cyble: Optional[URLAnalysisResult]
    CyRadar: Optional[URLAnalysisResult]
    DNS8: Optional[URLAnalysisResult]
    Dr_Web: Optional[URLAnalysisResult]
    Ermes: Optional[URLAnalysisResult]
    ESET: Optional[URLAnalysisResult]
    ESTsecurity: Optional[URLAnalysisResult]
    EmergingThreats: Optional[URLAnalysisResult]
    Emsisoft: Optional[URLAnalysisResult]
    Forcepoint_ThreatSeeker: Optional[URLAnalysisResult]
    Fortinet: Optional[URLAnalysisResult]
    G_Data: Optional[URLAnalysisResult]
    GCP_Abuse_Intelligence: Optional[URLAnalysisResult]
    Google_Safebrowsing: Optional[URLAnalysisResult]
    GreenSnow: Optional[URLAnalysisResult]
    Gridinsoft: Optional[URLAnalysisResult]
    Heimdal_Security: Optional[URLAnalysisResult]
    Hunt_io_Intelligence: Optional[URLAnalysisResult]
    IPsum: Optional[URLAnalysisResult]
    Juniper_Networks: Optional[URLAnalysisResult]
    Kaspersky: Optional[URLAnalysisResult]
    Lionic: Optional[URLAnalysisResult]
    Lumu: Optional[URLAnalysisResult]
    MalwarePatrol: Optional[URLAnalysisResult]
    MalwareURL: Optional[URLAnalysisResult]
    Malwared: Optional[URLAnalysisResult]
    Mimecast: Optional[URLAnalysisResult]
    Netcraft: Optional[URLAnalysisResult]
    OpenPhish: Optional[URLAnalysisResult]
    Phishing_Database: Optional[URLAnalysisResult]
    PhishFort: Optional[URLAnalysisResult]
    PhishLabs: Optional[URLAnalysisResult]
    Phishtank: Optional[URLAnalysisResult]
    PREBYTES: Optional[URLAnalysisResult]
    PrecisionSec: Optional[URLAnalysisResult]
    Quick_Heal: Optional[URLAnalysisResult]
    Quttera: Optional[URLAnalysisResult]
    SafeToOpen: Optional[URLAnalysisResult]
    Sansec_eComscan: Optional[URLAnalysisResult]
    Scantitan: Optional[URLAnalysisResult]
    SCUMWARE_org: Optional[URLAnalysisResult]
    Seclookup: Optional[URLAnalysisResult]
    SecureBrain: Optional[URLAnalysisResult]
    SOCRadar: Optional[URLAnalysisResult]
    Sophos: Optional[URLAnalysisResult]
    Spam404: Optional[URLAnalysisResult]
    StopForumSpam: Optional[URLAnalysisResult]
    Sucuri_SiteCheck: Optional[URLAnalysisResult]
    ThreatHive: Optional[URLAnalysisResult]
    Threatsourcing: Optional[URLAnalysisResult]
    Trustwave: Optional[URLAnalysisResult]
    Underworld: Optional[URLAnalysisResult]
    URLhaus: Optional[URLAnalysisResult]
    URLQuery: Optional[URLAnalysisResult]
    Viettel_Threat_Intelligence: Optional[URLAnalysisResult]
    VIPRE: Optional[URLAnalysisResult]
    VX_Vault: Optional[URLAnalysisResult]
    ViriBack: Optional[URLAnalysisResult]
    Webroot: Optional[URLAnalysisResult]
    Yandex_Safebrowsing: Optional[URLAnalysisResult]
    ZeroCERT: Optional[URLAnalysisResult]
    desenmascara_me: Optional[URLAnalysisResult]
    malwares_com_URL_checker: Optional[URLAnalysisResult]
    securolytics: Optional[URLAnalysisResult]
    Xcitium_Verdict_Cloud: Optional[URLAnalysisResult]
    zvelo: Optional[URLAnalysisResult]
    ZeroFox: Optional[URLAnalysisResult]


class URLAnalysisStats(ActionOutput):
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int
