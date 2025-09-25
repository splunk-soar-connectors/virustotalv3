from typing import Optional
from soar_sdk.action_results import ActionOutput, OutputField

from models.outputs.shared.main import TotalVotes
from models.outputs.ip_reputation.analysis import IPAnalysisResults, IPAnalysisStats
from models.outputs.shared.tls import HTTPSCertificate


class IPAttributes(ActionOutput):
    as_owner: str
    asn: int
    continent: Optional[str]
    country: Optional[str]
    jarm: str
    last_analysis_date: int = OutputField(cef_types=["timestamp"])
    last_analysis_results: IPAnalysisResults
    last_analysis_stats: IPAnalysisStats
    last_https_certificate: Optional[HTTPSCertificate]
    last_https_certificate_date: int = OutputField(cef_types=["timestamp"])
    last_modification_date: int = OutputField(cef_types=["timestamp"])
    network: str = OutputField(cef_types=["ip"])
    reputation: int
    total_votes: TotalVotes
    whois: Optional[str]
    whois_date: Optional[int] = OutputField(cef_types=["timestamp"])
    tags: list[str]
