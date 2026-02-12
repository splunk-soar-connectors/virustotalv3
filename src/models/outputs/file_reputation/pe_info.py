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


class PEDebugCodeView(ActionOutput):
    age: int
    guid: Optional[str]
    name: str
    offset: Optional[int]
    signature: str
    timestamp: Optional[str]


class PEFPO(ActionOutput):
    functions: int


class PEMisc(ActionOutput):
    datatype: int
    length: int
    is_unicode: int = OutputField(alias="unicode")
    data: str
    reserved: str


class PEReserved10(ActionOutput):
    value: str


class PEDebugEntry(ActionOutput):
    codeview: Optional[PEDebugCodeView]
    fpo: Optional[PEFPO]
    misc: Optional[PEMisc]
    offset: int
    reserved10: Optional[PEReserved10]
    size: int
    timestamp: str
    type: int
    type_str: str


class PEImportEntry(ActionOutput):
    imported_functions: list[str]
    library_name: str


class PEOverlay(ActionOutput):
    chi2: float
    entropy: float
    filetype: Optional[str]
    md5: str = OutputField(cef_types=["md5"])
    offset: int
    size: int


class PEResourceDetail(ActionOutput):
    chi2: float
    entropy: float
    filetype: Optional[str]
    lang: str
    sha256: str = OutputField(cef_types=["sha256"])
    type: str


class PESection(ActionOutput):
    entropy: float
    md5: str = OutputField(cef_types=["md5"])
    name: str
    raw_size: int
    virtual_address: int
    virtual_size: int


class PEInfo(ActionOutput):
    debug: Optional[list[PEDebugEntry]]
    entry_point: int
    exports: Optional[list[str]]
    imphash: str
    import_list: list[PEImportEntry]
    machine_type: str
    overlay: Optional[PEOverlay]
    resource_details: Optional[list[PEResourceDetail]]
    sections: list[PESection]
    timestamp: int = OutputField(cef_types=["timestamp"])
