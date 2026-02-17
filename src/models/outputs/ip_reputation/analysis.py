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


class IPAnalysisResult(ActionOutput):
    engine_name: Optional[str]
    category: Optional[str]
    method: Optional[str]
    result: Optional[str]


class IPAnalysisStats(ActionOutput):
    harmless: Optional[int]
    malicious: Optional[int]
    suspicious: Optional[int]
    timeout: Optional[int]
    undetected: Optional[int]


class IPAnalysisResults(ActionOutput):
    Acronis: Optional[IPAnalysisResult]
    SI_f33d: Optional[IPAnalysisResult] = OutputField(alias="0xSI_f33d")
    Abusix: Optional[IPAnalysisResult]
    ADMINUSLabs: Optional[IPAnalysisResult]
    Axur: Optional[IPAnalysisResult]
    ChainPatrol: Optional[IPAnalysisResult]
    Criminal_IP: Optional[IPAnalysisResult]
    AILabs_MONITORAPP: Optional[IPAnalysisResult]
    AlienVault: Optional[IPAnalysisResult]
    alphaMountain_ai: Optional[IPAnalysisResult]
    AlphaSOC: Optional[IPAnalysisResult]
    Antiy_AVL: Optional[IPAnalysisResult]
    ArcSight_Threat_Intelligence: Optional[IPAnalysisResult]
    AutoShun: Optional[IPAnalysisResult]
    benkow_cc: Optional[IPAnalysisResult]
    Bfore_Ai_PreCrime: Optional[IPAnalysisResult]
    BitDefender: Optional[IPAnalysisResult]
    Bkav: Optional[IPAnalysisResult]
    Blueliv: Optional[IPAnalysisResult]
    Certego: Optional[IPAnalysisResult]
    Chong_Lua_Dao: Optional[IPAnalysisResult]
    CINS_Army: Optional[IPAnalysisResult]
    Cluster25: Optional[IPAnalysisResult]
    CRDF: Optional[IPAnalysisResult]
    CSIS_Security_Group: Optional[IPAnalysisResult]
    Snort_IP_sample_list: Optional[IPAnalysisResult]
    CMC_Threat_Intelligence: Optional[IPAnalysisResult]
    Cyan: Optional[IPAnalysisResult]
    Cyble: Optional[IPAnalysisResult]
    CyRadar: Optional[IPAnalysisResult]
    DNS8: Optional[IPAnalysisResult]
    Dr_Web: Optional[IPAnalysisResult]
    Ermes: Optional[IPAnalysisResult]
    ESET: Optional[IPAnalysisResult]
    ESTsecurity: Optional[IPAnalysisResult]
    EmergingThreats: Optional[IPAnalysisResult]
    Emsisoft: Optional[IPAnalysisResult]
    Forcepoint_ThreatSeeker: Optional[IPAnalysisResult]
    Fortinet: Optional[IPAnalysisResult]
    G_Data: Optional[IPAnalysisResult]
    GCP_Abuse_Intelligence: Optional[IPAnalysisResult]
    Google_Safebrowsing: Optional[IPAnalysisResult]
    GreenSnow: Optional[IPAnalysisResult]
    Gridinsoft: Optional[IPAnalysisResult]
    Heimdal_Security: Optional[IPAnalysisResult]
    Hunt_io_Intelligence: Optional[IPAnalysisResult]
    IPsum: Optional[IPAnalysisResult]
    Juniper_Networks: Optional[IPAnalysisResult]
    Kaspersky: Optional[IPAnalysisResult]
    Lionic: Optional[IPAnalysisResult]
    Lumu: Optional[IPAnalysisResult]
    MalwarePatrol: Optional[IPAnalysisResult]
    MalwareURL: Optional[IPAnalysisResult]
    Malwared: Optional[IPAnalysisResult]
    Mimecast: Optional[IPAnalysisResult]
    Netcraft: Optional[IPAnalysisResult]
    OpenPhish: Optional[IPAnalysisResult]
    Phishing_Database: Optional[IPAnalysisResult]
    PhishFort: Optional[IPAnalysisResult]
    PhishLabs: Optional[IPAnalysisResult]
    Phishtank: Optional[IPAnalysisResult]
    PREBYTES: Optional[IPAnalysisResult]
    PrecisionSec: Optional[IPAnalysisResult]
    Quick_Heal: Optional[IPAnalysisResult]
    Quttera: Optional[IPAnalysisResult]
    SafeToOpen: Optional[IPAnalysisResult]
    Sansec_eComscan: Optional[IPAnalysisResult]
    Scantitan: Optional[IPAnalysisResult]
    SCUMWARE_org: Optional[IPAnalysisResult]
    Seclookup: Optional[IPAnalysisResult]
    SecureBrain: Optional[IPAnalysisResult]
    SOCRadar: Optional[IPAnalysisResult]
    Sophos: Optional[IPAnalysisResult]
    Spam404: Optional[IPAnalysisResult]
    StopForumSpam: Optional[IPAnalysisResult]
    Sucuri_SiteCheck: Optional[IPAnalysisResult]
    ThreatHive: Optional[IPAnalysisResult]
    Threatsourcing: Optional[IPAnalysisResult]
    Trustwave: Optional[IPAnalysisResult]
    Underworld: Optional[IPAnalysisResult]
    URLhaus: Optional[IPAnalysisResult]
    URLQuery: Optional[IPAnalysisResult]
    Viettel_Threat_Intelligence: Optional[IPAnalysisResult]
    VIPRE: Optional[IPAnalysisResult]
    VX_Vault: Optional[IPAnalysisResult]
    ViriBack: Optional[IPAnalysisResult]
    Webroot: Optional[IPAnalysisResult]
    Yandex_Safebrowsing: Optional[IPAnalysisResult]
    ZeroCERT: Optional[IPAnalysisResult]
    desenmascara_me: Optional[IPAnalysisResult]
    malwares_com_URL_checker: Optional[IPAnalysisResult]
    securolytics: Optional[IPAnalysisResult]
    Xcitium_Verdict_Cloud: Optional[IPAnalysisResult]
    zvelo: Optional[IPAnalysisResult]
    Zerofox: Optional[IPAnalysisResult]
