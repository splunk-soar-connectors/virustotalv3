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


class RDAPLink(ActionOutput):
    value: Optional[str] = OutputField(cef_types=["url"])
    rel: Optional[str]
    href: Optional[str] = OutputField(cef_types=["url"])
    type: Optional[str]
    title: Optional[str]
    media: Optional[str]
    href_lang: Optional[list[str]]


class RDAPEvent(ActionOutput):
    event_action: Optional[str]
    event_date: Optional[str] = OutputField(cef_types=["date"])
    event_actor: Optional[str]
    links: Optional[list[RDAPLink]]


class RDAPNotice(ActionOutput):
    title: Optional[str]
    description: Optional[list[str]]
    type: Optional[str]
    links: Optional[list[RDAPLink]]


class VCard(ActionOutput):
    name: Optional[str]
    type: Optional[str]
    values: Optional[list[str]]


class RDAPPublicID(ActionOutput):
    type: Optional[str]
    identifier: Optional[str]


class RDAPEntity(ActionOutput):
    vcard_array: Optional[list[VCard]]
    roles: Optional[list[str]]
    remarks: Optional[list[RDAPNotice]]
    events: Optional[list[RDAPEvent]]
    handle: Optional[str]
    public_ids: Optional[list[RDAPPublicID]]
    links: Optional[list[RDAPLink]]
    port43: Optional[str]
    networks: Optional[list[str]]
    autnums: Optional[list[str]]
    url: Optional[str] = OutputField(cef_types=["url"])
    lang: Optional[str]
    rdap_conformance: Optional[list[str]]


class RDAPSecureDNS(ActionOutput):
    zone_signed: Optional[bool]
    delegation_signed: Optional[bool]
    max_sig_life: Optional[int]
    ds_data: Optional[list[str]]
    key_data: Optional[list[str]]


class RDAPNameserver(ActionOutput):
    ldh_name: Optional[str]
    events: Optional[list[RDAPEvent]]
    object_class_name: Optional[str]
    status: Optional[list[str]]
    handle: Optional[str]
    unicode_name: Optional[str]
    links: Optional[list[RDAPLink]]
    notices: Optional[list[RDAPNotice]]
    lang: Optional[str]
    port43: Optional[str]
    entities: Optional[list[RDAPEntity]]
    remarks: Optional[list[RDAPNotice]]


class RDAP(ActionOutput):
    handle: Optional[str]
    ldh_name: Optional[str]
    events: Optional[list[RDAPEvent]]
    notices: Optional[list[RDAPNotice]]
    nameservers: Optional[list[RDAPNameserver]]
    rdap_conformance: Optional[list[str]]
    entities: Optional[list[RDAPEntity]]
    object_class_name: Optional[str]
    status: Optional[list[str]]
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
