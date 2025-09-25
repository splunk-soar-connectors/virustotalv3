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
    authority_key_identifier: CAKeyIdentifier
    subject_key_identifier: str
    subject_alternative_name: list[str]
    certificate_policies: list[str]
    key_usage: list[str]
    extended_key_usage: list[str]
    crl_distribution_points: list[str] = OutputField(cef_types=["url"])
    ca_information_access: CAInformationAccess
    CA: bool
    certificate_transparency_signature: str = OutputField(
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
