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


class PDFInfo(ActionOutput):
    acroform: Optional[int]
    autoaction: Optional[int]
    embedded_file: Optional[int]
    encrypted: Optional[int]
    flash: Optional[int]
    header: Optional[str]
    javascript: Optional[int]
    jbig2_compression: Optional[int]
    js: Optional[int]
    num_endobj: Optional[int]
    num_endstream: Optional[int]
    num_launch_actions: Optional[int]
    num_obj: Optional[int]
    num_object_streams: Optional[int]
    num_pages: Optional[int]
    num_stream: Optional[int]
    openaction: Optional[int]
    startxref: Optional[int]
    suspicious_colors: Optional[int]
    trailer: Optional[int]
    xfa: Optional[int]
    xref: Optional[int]
