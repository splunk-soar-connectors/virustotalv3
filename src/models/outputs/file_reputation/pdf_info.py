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
from soar_sdk.action_results import ActionOutput


class PDFInfo(ActionOutput):
    acroform: int
    autoaction: int
    embedded_file: int
    encrypted: int
    flash: int
    header: str
    javascript: int
    jbig2_compression: int
    js: int
    num_endobj: int
    num_endstream: int
    num_launch_actions: int
    num_obj: int
    num_object_streams: int
    num_pages: int
    num_stream: int
    openaction: int
    startxref: int
    suspicious_colors: int
    trailer: int
    xfa: int
    xref: int
