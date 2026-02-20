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
from soar_sdk.action_results import ActionOutput


class FileAnalysisStats(ActionOutput):
    malicious: Optional[int]
    suspicious: Optional[int]
    undetected: Optional[int]
    harmless: Optional[int]
    timeout: Optional[int]
    confirmed_timeout: Optional[int]
    failure: Optional[int]
    type_unsupported: Optional[int]


class FileAnalysisResult(ActionOutput):
    category: Optional[str]
    engine_name: Optional[str]
    engine_version: Optional[str]
    engine_update: Optional[str]
    method: Optional[str]
    result: Optional[str]  # Can be null
    vendor: Optional[str]


class FileAnalysisResults(ActionOutput):
    Bkav: Optional[FileAnalysisResult]
    Lionic: Optional[FileAnalysisResult]
    MicroWorld_eScan: Optional[FileAnalysisResult]
    ClamAV: Optional[FileAnalysisResult]
    CTX: Optional[FileAnalysisResult]
    Skyhigh: Optional[FileAnalysisResult]
    ALYac: Optional[FileAnalysisResult]
    Malwarebytes: Optional[FileAnalysisResult]
    Zillya: Optional[FileAnalysisResult]
    Sangfor: Optional[FileAnalysisResult]
    K7AntiVirus: Optional[FileAnalysisResult]
    K7GW: Optional[FileAnalysisResult]
    CrowdStrike: Optional[FileAnalysisResult]
    Baidu: Optional[FileAnalysisResult]
    Symantec: Optional[FileAnalysisResult]
    ESET_NOD32: Optional[FileAnalysisResult]
    TrendMicro_HouseCall: Optional[FileAnalysisResult]
    Avast: Optional[FileAnalysisResult]
    Cynet: Optional[FileAnalysisResult]
    Kaspersky: Optional[FileAnalysisResult]
    BitDefender: Optional[FileAnalysisResult]
    NANO_Antivirus: Optional[FileAnalysisResult]
    SUPERAntiSpyware: Optional[FileAnalysisResult]
    Rising: Optional[FileAnalysisResult]
    Emsisoft: Optional[FileAnalysisResult]
    F_Secure: Optional[FileAnalysisResult]
    DrWeb: Optional[FileAnalysisResult]
    VIPRE: Optional[FileAnalysisResult]
    TrendMicro: Optional[FileAnalysisResult]
    McAfeeD: Optional[FileAnalysisResult]
    CMC: Optional[FileAnalysisResult]
    Sophos: Optional[FileAnalysisResult]
    Ikarus: Optional[FileAnalysisResult]
    Jiangmin: Optional[FileAnalysisResult]
    Google: Optional[FileAnalysisResult]
    Avira: Optional[FileAnalysisResult]
    Antiy_AVL: Optional[FileAnalysisResult]
    Kingsoft: Optional[FileAnalysisResult]
    Microsoft: Optional[FileAnalysisResult]
    Gridinsoft: Optional[FileAnalysisResult]
    Xcitium: Optional[FileAnalysisResult]
    Acrabit: Optional[FileAnalysisResult]
    ViRobot: Optional[FileAnalysisResult]
    ZoneAlarm: Optional[FileAnalysisResult]
    GData: Optional[FileAnalysisResult]
    Varist: Optional[FileAnalysisResult]
    AhnLab_V3: Optional[FileAnalysisResult]
    Acronis: Optional[FileAnalysisResult]
    VBA32: Optional[FileAnalysisResult]
    TACHYON: Optional[FileAnalysisResult]
    Zoner: Optional[FileAnalysisResult]
    Tencent: Optional[FileAnalysisResult]
    Yandex: Optional[FileAnalysisResult]
    TrellixENS: Optional[FileAnalysisResult]
    huorong: Optional[FileAnalysisResult]
    MaxSecure: Optional[FileAnalysisResult]
    Fortinet: Optional[FileAnalysisResult]
    AVG: Optional[FileAnalysisResult]
    Panda: Optional[FileAnalysisResult]
    alibabacloud: Optional[FileAnalysisResult]
    VirIT: Optional[FileAnalysisResult]
    CAT_QuickHeal: Optional[FileAnalysisResult]
    Avast_Mobile: Optional[FileAnalysisResult]
    SymantecMobileInsight: Optional[FileAnalysisResult]
    BitDefenderFalx: Optional[FileAnalysisResult]
    DeepInstinct: Optional[FileAnalysisResult]
    Elastic: Optional[FileAnalysisResult]
    APEX: Optional[FileAnalysisResult]
    Paloalto: Optional[FileAnalysisResult]
    Trapmine: Optional[FileAnalysisResult]
    Alibaba: Optional[FileAnalysisResult]
    Webroot: Optional[FileAnalysisResult]
    Cylance: Optional[FileAnalysisResult]
    SentinelOne: Optional[FileAnalysisResult]
    tehtris: Optional[FileAnalysisResult]
    Trustlook: Optional[FileAnalysisResult]
    OpenPhish: Optional[FileAnalysisResult]
    Nucleon: Optional[FileAnalysisResult]
