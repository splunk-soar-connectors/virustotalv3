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


class RDAPLink(ActionOutput):
    value: str = OutputField(cef_types=["url"])
    rel: str
    href: str = OutputField(cef_types=["url"])
    type: str
    title: str
    media: str
    href_lang: list[str]


class RDAPEvent(ActionOutput):
    event_action: str
    event_date: str = OutputField(cef_types=["date"])
    event_actor: str
    links: list[RDAPLink]


class RDAPNotice(ActionOutput):
    title: str
    description: list[str]
    type: str
    links: list[RDAPLink]


class VCard(ActionOutput):
    name: str
    type: str
    values: list[str]


class RDAPPublicID(ActionOutput):
    type: str
    identifier: str


class RDAPEntity(ActionOutput):
    vcard_array: list[VCard]
    roles: list[str]
    remarks: list[RDAPNotice]
    events: list[RDAPEvent]
    handle: str
    public_ids: list[RDAPPublicID]
    links: list[RDAPLink]
    port43: str
    networks: list[str]
    autnums: list[str]
    url: str = OutputField(cef_types=["url"])
    lang: str
    rdap_conformance: list[str]


class RDAPSecureDNS(ActionOutput):
    zone_signed: bool
    delegation_signed: bool
    max_sig_life: int
    ds_data: list[str]
    key_data: list[str]


class RDAPNameserver(ActionOutput):
    ldh_name: str
    events: list[RDAPEvent]
    object_class_name: str
    status: list[str]
    handle: str
    unicode_name: str
    links: list[RDAPLink]
    notices: list[RDAPNotice]
    lang: str
    port43: str
    entities: list[RDAPEntity]
    remarks: list[RDAPNotice]


class RDAP(ActionOutput):
    handle: str
    ldh_name: str
    events: list[RDAPEvent]
    notices: list[RDAPNotice]
    nameservers: list[RDAPNameserver]
    rdap_conformance: list[str]
    entities: list[RDAPEntity]
    object_class_name: str
    status: list[str]
    secure_dns: RDAPSecureDNS
    port43: str
    unicode_name: str
    punycode: str
    type: str
    links: list[RDAPLink]
    switch_name: str
    public_ids: list[RDAPPublicID]
    lang: str
    remarks: list[str]
    nask0_state: str
    variants: list[str]
