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
    age: Optional[int]
    guid: Optional[str]
    name: Optional[str]
    offset: Optional[int]
    signature: Optional[str]
    timestamp: Optional[str]


class PEFPO(ActionOutput):
    functions: Optional[int]


class PEMisc(ActionOutput):
    datatype: Optional[int]
    length: Optional[int]
    is_unicode: Optional[int] = OutputField(alias="unicode")
    data: Optional[str]
    reserved: Optional[str]


class PEReserved10(ActionOutput):
    value: Optional[str]


class PEDebugEntry(ActionOutput):
    codeview: Optional[PEDebugCodeView]
    fpo: Optional[PEFPO]
    misc: Optional[PEMisc]
    offset: Optional[int]
    reserved10: Optional[PEReserved10]
    size: Optional[int]
    timestamp: Optional[str]
    type: Optional[int]
    type_str: Optional[str]


class PEImportEntry(ActionOutput):
    imported_functions: Optional[list[str]]
    library_name: Optional[str]


class PEOverlay(ActionOutput):
    chi2: Optional[float]
    entropy: Optional[float]
    filetype: Optional[str]
    md5: Optional[str] = OutputField(cef_types=["md5"])
    offset: Optional[int]
    size: Optional[int]


class PEResourceDetail(ActionOutput):
    chi2: Optional[float]
    entropy: Optional[float]
    filetype: Optional[str]
    lang: Optional[str]
    sha256: Optional[str] = OutputField(cef_types=["sha256"])
    type: Optional[str]


class PESection(ActionOutput):
    entropy: Optional[float]
    md5: Optional[str] = OutputField(cef_types=["md5"])
    name: Optional[str]
    raw_size: Optional[int]
    virtual_address: Optional[int]
    virtual_size: Optional[int]


class PEInfo(ActionOutput):
    debug: Optional[list[PEDebugEntry]]
    entry_point: Optional[int]
    exports: Optional[list[str]]
    imphash: Optional[str]
    import_list: Optional[list[PEImportEntry]]
    machine_type: Optional[str]
    overlay: Optional[PEOverlay]
    resource_details: Optional[list[PEResourceDetail]]
    sections: Optional[list[PESection]]
    timestamp: Optional[int] = OutputField(cef_types=["timestamp"])
