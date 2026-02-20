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
from soar_sdk.action_results import ActionOutput, OutputField
from typing import Optional


class PopularityRank(ActionOutput):
    rank: Optional[int]
    timestamp: Optional[int] = OutputField(
        cef_types=["timestamp"], example_values=[1613635210]
    )


class PopularityRanks(ActionOutput):
    Majestic: Optional[PopularityRank]
    Statvoo: Optional[PopularityRank]
    Alexa: Optional[PopularityRank]
    Cisco_Umbrella: Optional[PopularityRank]
    Quantcast: Optional[PopularityRank]
    Cloudflare_Radar: Optional[PopularityRank]
