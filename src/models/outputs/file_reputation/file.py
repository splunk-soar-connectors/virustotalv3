from typing import Optional
from soar_sdk.action_results import ActionOutput, OutputField

from models.outputs.shared import TotalVotes
from models.outputs.file_reputation.sandbox import FileSandboxVerdicts
from models.outputs.file_reputation.analysis import (
    FileAnalysisStats,
    FileAnalysisResults,
)
from models.outputs.file_reputation.pdf_info import PDFInfo
from models.outputs.file_reputation.detectiteasy import DetectItEasyResult
from models.outputs.file_reputation.pe_info import PEInfo
from models.outputs.file_reputation.popular_threat_classification import (
    PopularThreatClassification,
)


class TrID(ActionOutput):
    file_type: str
    probability: int


class FileConditions(ActionOutput):
    raw_md5: str = OutputField(cef_types=["md5"])
    dhash: str = OutputField(cef_types=["hash"])


class KnownFileDistributors(ActionOutput):
    distributors: list[str]
    filenames: list[str]
    products: list[str]
    data_sources: list[str]


class FileAttributes(ActionOutput):
    first_submission_date: int = OutputField(cef_types=["timestamp"])
    known_distributors: KnownFileDistributors
    type_tag: str
    md5: str = OutputField(cef_types=["md5"])
    sandbox_verdicts: FileSandboxVerdicts
    sha256: str = OutputField(cef_types=["sha256"])
    last_submission_date: int = OutputField(cef_types=["timestamp"])
    trid: list[TrID]
    filecondis: FileConditions
    last_analysis_stats: FileAnalysisStats
    ssdeep: str
    type_description: str
    magic: str
    total_votes: TotalVotes
    times_submitted: int
    tags: list[str]
    last_modification_date: int = OutputField(cef_types=["timestamp"])
    meaningful_name: str
    tlsh: str
    first_seen_itw_date: int = OutputField(cef_types=["timestamp"])
    size: int
    last_analysis_date: int = OutputField(cef_types=["timestamp"])
    sha1: str = OutputField(cef_types=["sha1"])
    reputation: int
    unique_sources: int
    last_analysis_results: FileAnalysisResults
    type_extension: str
    magika: str
    type_tags: list[str]
    names: list[str]
    pdf_info: Optional[PDFInfo]
    detectiteasy: Optional[DetectItEasyResult]
    pe_info: Optional[PEInfo]
    popular_threat_classification: Optional[PopularThreatClassification]
