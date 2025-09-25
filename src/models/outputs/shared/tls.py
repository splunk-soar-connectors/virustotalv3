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
from typing import Optional


class CertificateSignature(ActionOutput):
    signature: str
    signature_algorithm: str


class CAKeyIdentifier(ActionOutput):
    keyid: str


class CAInformationAccess(ActionOutput):
    CA_Issuers: str = OutputField(cef_types=["url"])
    OCSP: str = OutputField(cef_types=["url"])


class CertificateExtensions(ActionOutput):
    authority_key_identifier: Optional[CAKeyIdentifier]
    subject_key_identifier: Optional[str]
    subject_alternative_name: Optional[list[str]]
    certificate_policies: Optional[list[str]]
    key_usage: Optional[list[str]]
    extended_key_usage: Optional[list[str]]
    crl_distribution_points: Optional[list[str]] = OutputField(cef_types=["url"])
    ca_information_access: Optional[CAInformationAccess]
    CA: Optional[bool]
    certificate_transparency_signature: Optional[str] = OutputField(
        alias="1_3_6_1_4_1_11129_2_4_2"
    )


class CertificateValidity(ActionOutput):
    not_before: str = OutputField(cef_types=["date"])
    not_after: str = OutputField(cef_types=["date"])


class RSAParameters(ActionOutput):
    exponent: str
    key_size: int
    modulus: str


class CertificatePublicKey(ActionOutput):
    algorithm: str
    rsa: Optional[RSAParameters]


class CertificateSubjectName(ActionOutput):
    CN: str
    O: str  # noqa: E741
    C: str
    L: Optional[str]
    ST: Optional[str]


class HTTPSCertificate(ActionOutput):
    cert_signature: CertificateSignature
    extensions: CertificateExtensions
    validity: CertificateValidity
    size: int
    version: str
    public_key: CertificatePublicKey
    thumbprint_sha256: str
    thumbprint: str
    serial_number: str
    issuer: CertificateSubjectName
    subject: CertificateSubjectName
