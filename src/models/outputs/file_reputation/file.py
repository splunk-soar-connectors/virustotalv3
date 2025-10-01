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

from models.outputs.shared.main import TotalVotes
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
    raw_md5: Optional[str] = OutputField(cef_types=["md5"])
    dhash: Optional[str] = OutputField(cef_types=["hash"])


class KnownFileDistributors(ActionOutput):
    distributors: list[str]
    filenames: list[str]
    products: list[str]
    data_sources: list[str]


class FileAttributes(ActionOutput):
    first_submission_date: int = OutputField(cef_types=["timestamp"])
    known_distributors: Optional[KnownFileDistributors]
    type_tag: str
    md5: str = OutputField(cef_types=["md5"])
    sandbox_verdicts: FileSandboxVerdicts
    sha256: str = OutputField(cef_types=["sha256"])
    last_submission_date: int = OutputField(cef_types=["timestamp"])
    trid: list[TrID]
    filecondis: Optional[FileConditions]
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
    first_seen_itw_date: Optional[int] = OutputField(cef_types=["timestamp"])
    size: int
    last_analysis_date: int = OutputField(cef_types=["timestamp"])
    sha1: str = OutputField(cef_types=["sha1"])
    reputation: int
    unique_sources: int
    last_analysis_results: Optional[FileAnalysisResults]
    type_extension: str
    magika: Optional[str]
    type_tags: list[str]
    names: list[str]
    pdf_info: Optional[PDFInfo]
    detectiteasy: Optional[DetectItEasyResult]
    pe_info: Optional[PEInfo]
    popular_threat_classification: Optional[PopularThreatClassification]
