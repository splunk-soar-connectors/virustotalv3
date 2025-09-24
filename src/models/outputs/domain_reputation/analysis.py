from soar_sdk.action_results import ActionOutput, OutputField
from typing import Optional


class DomainAnalysisResult(ActionOutput):
    category: str = OutputField(example_values=["malicious"])
    engine_name: str = OutputField(example_values=["CMC"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["Trojan.GenericKD.3275421"])


class DomainAnalysisResults(ActionOutput):
    Acronis: Optional[DomainAnalysisResult]
    SI_f33d: Optional[DomainAnalysisResult] = OutputField(alias="0xSI_f33d")
    Abusix: Optional[DomainAnalysisResult]
    ADMINUSLabs: Optional[DomainAnalysisResult]
    Axur: Optional[DomainAnalysisResult]
    ChainPatrol: Optional[DomainAnalysisResult]
    Criminal_IP: Optional[DomainAnalysisResult]
    AILabs_MONITORAPP: Optional[DomainAnalysisResult]
    AlienVault: Optional[DomainAnalysisResult]
    alphaMountain_ai: Optional[DomainAnalysisResult]
    AlphaSOC: Optional[DomainAnalysisResult]
    Antiy_AVL: Optional[DomainAnalysisResult]
    ArcSight_Threat_Intelligence: Optional[DomainAnalysisResult]
    AutoShun: Optional[DomainAnalysisResult]
    benkow_cc: Optional[DomainAnalysisResult]
    Bfore_Ai_PreCrime: Optional[DomainAnalysisResult]
    BitDefender: Optional[DomainAnalysisResult]
    Bkav: Optional[DomainAnalysisResult]
    Blueliv: Optional[DomainAnalysisResult]
    Certego: Optional[DomainAnalysisResult]
    Chong_Lua_Dao: Optional[DomainAnalysisResult]
    CINS_Army: Optional[DomainAnalysisResult]
    Cluster25: Optional[DomainAnalysisResult]
    CRDF: Optional[DomainAnalysisResult]
    CSIS_Security_Group: Optional[DomainAnalysisResult]
    Snort_IP_sample_list: Optional[DomainAnalysisResult]
    CMC_Threat_Intelligence: Optional[DomainAnalysisResult]
    Cyan: Optional[DomainAnalysisResult]
    Cyble: Optional[DomainAnalysisResult]
    CyRadar: Optional[DomainAnalysisResult]
    DNS8: Optional[DomainAnalysisResult]
    Dr_Web: Optional[DomainAnalysisResult]
    Ermes: Optional[DomainAnalysisResult]
    ESET: Optional[DomainAnalysisResult]
    ESTsecurity: Optional[DomainAnalysisResult]
    EmergingThreats: Optional[DomainAnalysisResult]
    Emsisoft: Optional[DomainAnalysisResult]
    Forcepoint_ThreatSeeker: Optional[DomainAnalysisResult]
    Fortinet: Optional[DomainAnalysisResult]
    G_Data: Optional[DomainAnalysisResult]
    GCP_Abuse_Intelligence: Optional[DomainAnalysisResult]
    Google_Safebrowsing: Optional[DomainAnalysisResult]
    GreenSnow: Optional[DomainAnalysisResult]
    Gridinsoft: Optional[DomainAnalysisResult]
    Heimdal_Security: Optional[DomainAnalysisResult]
    Hunt_io_Intelligence: Optional[DomainAnalysisResult]
    IPsum: Optional[DomainAnalysisResult]
    Juniper_Networks: Optional[DomainAnalysisResult]
    Kaspersky: Optional[DomainAnalysisResult]
    Lionic: Optional[DomainAnalysisResult]
    Lumu: Optional[DomainAnalysisResult]
    MalwarePatrol: Optional[DomainAnalysisResult]
    MalwareURL: Optional[DomainAnalysisResult]
    Malwared: Optional[DomainAnalysisResult]
    Mimecast: Optional[DomainAnalysisResult]
    Netcraft: Optional[DomainAnalysisResult]
    OpenPhish: Optional[DomainAnalysisResult]
    Phishing_Database: Optional[DomainAnalysisResult]
    PhishFort: Optional[DomainAnalysisResult]
    PhishLabs: Optional[DomainAnalysisResult]
    Phishtank: Optional[DomainAnalysisResult]
    PREBYTES: Optional[DomainAnalysisResult]
    PrecisionSec: Optional[DomainAnalysisResult]
    Quick_Heal: Optional[DomainAnalysisResult]
    Quttera: Optional[DomainAnalysisResult]
    SafeToOpen: Optional[DomainAnalysisResult]
    Sansec_eComscan: Optional[DomainAnalysisResult]
    Scantitan: Optional[DomainAnalysisResult]
    SCUMWARE_org: Optional[DomainAnalysisResult]
    Seclookup: Optional[DomainAnalysisResult]
    SecureBrain: Optional[DomainAnalysisResult]
    SOCRadar: Optional[DomainAnalysisResult]
    Sophos: Optional[DomainAnalysisResult]
    Spam404: Optional[DomainAnalysisResult]
    StopForumSpam: Optional[DomainAnalysisResult]
    Sucuri_SiteCheck: Optional[DomainAnalysisResult]
    ThreatHive: Optional[DomainAnalysisResult]
    Threatsourcing: Optional[DomainAnalysisResult]
    Trustwave: Optional[DomainAnalysisResult]
    Underworld: Optional[DomainAnalysisResult]
    URLhaus: Optional[DomainAnalysisResult]
    URLQuery: Optional[DomainAnalysisResult]
    Viettel_Threat_Intelligence: Optional[DomainAnalysisResult]
    VIPRE: Optional[DomainAnalysisResult]
    VX_Vault: Optional[DomainAnalysisResult]
    ViriBack: Optional[DomainAnalysisResult]
    Webroot: Optional[DomainAnalysisResult]
    Yandex_Safebrowsing: Optional[DomainAnalysisResult]
    ZeroCERT: Optional[DomainAnalysisResult]
    desenmascara_me: Optional[DomainAnalysisResult]
    malwares_com_URL_checker: Optional[DomainAnalysisResult]
    securolytics: Optional[DomainAnalysisResult]
    Xcitium_Verdict_Cloud: Optional[DomainAnalysisResult]
    zvelo: Optional[DomainAnalysisResult]
    ZeroFox: Optional[DomainAnalysisResult]


class DomainAnalysisStats(ActionOutput):
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int

class AnalysisResults(ActionOutput):
    results: list[DomainAnalysisResult]