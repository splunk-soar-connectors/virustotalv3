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

from soar_sdk.action_results import ActionOutput, OutputField


class QuotaGroup(ActionOutput):
    allowed: int = OutputField(example_values=[500])
    inherited_from: str = OutputField(example_values=["vt_group"])
    used: int = OutputField(example_values=[2])


class QuotaUser(ActionOutput):
    allowed: int = OutputField(example_values=[500])
    used: int = OutputField(example_values=[2])


class ApiRequestsDailyOutput(ActionOutput):
    group: QuotaGroup
    user: QuotaUser


class ApiRequestsHourlyOutput(ActionOutput):
    group: QuotaGroup
    user: QuotaUser


class ApiRequestsMonthlyOutput(ActionOutput):
    group: QuotaGroup
    user: QuotaUser


class CollectionsCreationMonthlyOutput(ActionOutput):
    user: QuotaUser


class IntelligenceDownloadsMonthlyOutput(ActionOutput):
    user: QuotaUser


class IntelligenceGraphsPrivateOutput(ActionOutput):
    user: QuotaUser


class IntelligenceHuntingRulesOutput(ActionOutput):
    user: QuotaUser


class IntelligenceRetrohuntJobsMonthlyOutput(ActionOutput):
    user: QuotaUser


class IntelligenceSearchesMonthlyOutput(ActionOutput):
    user: QuotaUser


class IntelligenceVtdiffCreationMonthlyOutput(ActionOutput):
    user: QuotaUser


class MonitorStorageBytesOutput(ActionOutput):
    user: QuotaUser


class MonitorStorageFilesOutput(ActionOutput):
    user: QuotaUser


class MonitorUploadedBytesOutput(ActionOutput):
    user: QuotaUser


class MonitorUploadedFilesOutput(ActionOutput):
    user: QuotaUser


class PrivateScansMonthlyOutput(ActionOutput):
    user: QuotaUser


class PrivateScansPerMinuteOutput(ActionOutput):
    user: QuotaUser
