import httpx

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from models.outputs.shared import APILinks

from models.outputs.domain_reputation.domain import DomainAttributes

from utils import sanitize_key_names

logger = getLogger()


class Asset(BaseAsset):
    apikey: str = AssetField(required=True, description="VirusTotal API key")
    poll_interval: float = AssetField(
        required=False,
        description="Number of minutes to poll for a detonation result (Default: 5)",
        default=5.0,
    )
    waiting_time: float = AssetField(
        required=False,
        description="Number of seconds to wait before polling for a detonation result (Default: 0)",
        default=0.0,
    )
    rate_limit: bool = AssetField(
        required=False,
        description="Limit number of requests to 4 per minute",
        default=True,
    )
    timeout: float = AssetField(
        required=False,
        description="Request Timeout (Default: 30 seconds)",
        default=30.0,
    )
    cache_reputation_checks: bool = AssetField(
        required=False, description="Cache virustotal reputation checks", default=True
    )
    cache_expiration_interval: float = AssetField(
        required=False,
        description="Number of seconds until cached reputation checks expire. Any other value than positive integer will disable caching (Default: 3600 seconds)",
        default=3600.0,
    )
    cache_size: float = AssetField(
        required=False,
        description="Maximum number of entries in cache. Values of zero or less will not limit size and decimal value will be converted to floor value (Default: 1000)",
        default=1000.0,
    )

    def get_client(self) -> httpx.Client:
        headers = {
            "x-apikey": self.apikey,
            "Content-Type": "application/json",
        }
        return httpx.Client(
            base_url="https://www.virustotal.com/api/v3/",
            timeout=self.timeout,
            headers=headers,
        )


app = App(
    name="virustotalv3",
    app_type="reputation",
    logo="logo_virustotalv3.svg",
    logo_dark="logo_virustotalv3_dark.svg",
    product_vendor="VirusTotal",
    product_name="VirusTotal v3",
    publisher="Splunk",
    appid="3fe4875d-a4a7-47d3-9ef1-f9e63a6653a4",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    client = asset.get_client()
    response = client.get("files/upload_url")

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise AssetMisconfiguration(
            "Failed to connect to VirusTotal. Please check the API key."
        ) from e

    logger.debug(f"VirusTotal response: {response.json()}")

    if "data" not in response.json():
        raise ActionFailure(
            "VirusTotal response did not contain any data. This is likely an issue with the VirusTotal service."
        )


class DomainReputationParams(Params):
    domain: str = Param(
        description="Domain to query", primary=True, cef_types=["domain"]
    )


class DomainReputationOutput(ActionOutput):
    id: str = OutputField(cef_types=["domain"], example_values=["test.com"])
    type: str = OutputField(example_values=["domain"])
    links: APILinks
    attributes: DomainAttributes


@app.action(description="Queries VirusTotal for domain info", action_type="investigate")
def domain_reputation(params: DomainReputationParams, soar: SOARClient, asset: Asset) -> DomainReputationOutput:
    client = asset.get_client()

    response = client.get(f"domains/{params.domain}")
    response.raise_for_status()

    logger.debug(f"VirusTotal response: {response.json()}")
    if not (data := response.json().get("data")):
        raise ActionFailure(f"No data found for domain {params.domain}")

    sanitized_data = sanitize_key_names(data)
    logger.debug(f"Sanitized data: {sanitized_data}")

    return DomainReputationOutput(**sanitized_data)


class FileReputationParams(Params):
    hash: str = Param(
        description="File hash to query",
        primary=True,
        cef_types=["hash", "sha256", "sha1", "md5"],
    )


class FileAttributes(ActionOutput):
    authentihash: str = OutputField(
        example_values=[
            "999999990b465f7bd1e7568640397f01fc4f8819ce6f0c1415690ecee646464cec"
        ]
    )
    creation_date: float = OutputField(example_values=[1410950077])
    detectiteasy: DetectiteasyOutput
    first_submission_date: float = OutputField(example_values=[1612961082])
    last_analysis_date: float = OutputField(example_values=[1613635130])
    last_analysis_results: list[LastAnalysisResultsOutput]
    last_analysis_stats: LastAnalysisStatsOutput
    last_modification_date: float = OutputField(example_values=[1613635210])
    last_submission_date: float = OutputField(example_values=[1613635130])
    magic: str = OutputField(example_values=["a python2.7\\015script text executable"])
    md5: str = OutputField(
        cef_types=["md5"], example_values=["2e65153f2c49c91a0206ee7a8c00e659"]
    )
    meaningful_name: str = OutputField(example_values=["update_cr.py"])
    names: str = OutputField(example_values=["update_cr.py"])
    pdf_info: PdfInfoOutput
    pe_info: PeInfoOutput
    popular_threat_classification: PopularThreatClassificationOutput
    reputation: float = OutputField(example_values=[0])
    sandbox_verdicts: SandboxVerdictsOutput
    sha1: str = OutputField(
        cef_types=["sha1"], example_values=["9999969a19142292710254cde97df84e46dfe33a"]
    )
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "9999999ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"
        ],
    )
    signature_info: SignatureInfoOutput
    size: float = OutputField(example_values=[6285])
    ssdeep: str = OutputField(
        example_values=[
            "192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygiINVALIDu7ThPBLkv:pq7Mgg0/NdMu/1BLkv"
        ]
    )
    tags: str = OutputField(example_values=["python"])
    times_submitted: float = OutputField(example_values=[13])
    tlsh: str = OutputField(
        example_values=[
            "9999999905AC5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC"
        ]
    )
    total_votes: TotalVotesOutput
    trid: list[TridOutput]
    type_description: str = OutputField(example_values=["Python"])
    type_extension: str = OutputField(example_values=["py"])
    type_tag: str = OutputField(example_values=["python"])
    unique_sources: float = OutputField(example_values=[1])
    vhash: str = OutputField(
        example_values=["999996657d755510804011z9005b9z25z12z3afz"]
    )


class FileReputationOutput(ActionOutput):
    attributes: FileAttributes
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=["9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"],
    )
    links: APILinks
    type: str = OutputField(example_values=["file"])


@app.action(description="Queries VirusTotal for file reputation info", action_type="investigate")
def file_reputation(params: FileReputationParams, soar: SOARClient, asset: Asset) -> FileReputationOutput:
    raise NotImplementedError()


class GetFileParams(Params):
    hash: str = Param(
        description="Hash of file to get",
        primary=True,
        cef_types=["hash", "sha256", "sha1", "md5"],
    )


@app.action(
    description="Downloads a file from VirusTotal and adds it to the vault",
    action_type="investigate",
)
def get_file(params: GetFileParams, soar: SOARClient, asset: Asset) -> ActionOutput:
    raise NotImplementedError()


class IpReputationParams(Params):
    ip: str = Param(description="IP to query", primary=True, cef_types=["ip", "ipv6"])


class CrowdsourcedContextOutput(ActionOutput):
    detail: str = OutputField(example_values=["A domain seen in a CnC panel URL for the Oski malware resolved to this IP address"])
    severity: str = OutputField(example_values=["high"])
    source: str = OutputField(example_values=["benkow.cc"])
    timestamp: float = OutputField(example_values=[1622592000])
    title: str = OutputField(example_values=["CnC Panel"])


class LastAnalysisResultsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CRDF"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])
    vendor: str = OutputField(example_values=["Symantec"])


class LastAnalysisStatsOutput(ActionOutput):
    harmless: float = OutputField(example_values=[86])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[0])
    timeout: float = OutputField(example_values=[0])
    undetected: float = OutputField(example_values=[11])


class CertSignatureOutput(ActionOutput):
    signature: str = OutputField(
        example_values=[
            "9999999991eed2a66b7aef3c70912cd032acbd2c8791021a3c8cb90b38c579d5fa02d04e4e897b1762981b455d77cea92c56bcf902451a76148582a1e80acc1aeb2a0d72f7e8db8739f874e83a48553311eb3cfe48a0d065a309cedf35930ae3e2cb0d4dca8dba64dc7b5f707debac4f28ce313db8623e235790002b37a8dbc63c99276335c4a59faf1957d5384fc318c56b159e51213c21699e328821f64efc433d74372962d6d160f92b5f1dbbc4e8e11c74ce673e8c52f6270c40c1192cf7bf2bbf44660818b8999085388ac8949332f178b294d409334e8d70ca051a5a7ed53df82e58a46ee2c07afa08f0e0f9ea87311f1a8e79ad3406292e811a5c6"
        ]
    )
    signature_algorithm: str = OutputField(example_values=["sha256RSA"])


class n4Output(ActionOutput):
    pass


class n2Output(ActionOutput):
    n4: n4Output


class n11129Output(ActionOutput):
    n2: n2Output


class n1Output(ActionOutput):
    pass


class n6Output(ActionOutput):
    n1: n1Output


class n3Output(ActionOutput):
    n6: n6Output


class AuthorityKeyIdentifierOutput(ActionOutput):
    keyid: str = OutputField(example_values=["999997faf85cdee95cd3d9cd0e24614f371351d27"])


class CaInformationAccessOutput(ActionOutput):
    CA_Issuers: str = OutputField(example_values=["http://pki.goog/repo/certs/gts1c3.der"], alias="CA Issuers")
    OCSP: str = OutputField(example_values=["http://ocsp.pki.goog/gts1c3"])


class ExtensionsOutput(ActionOutput):
    n1: n1Output
    CA: bool = OutputField(example_values=[True])
    authority_key_identifier: AuthorityKeyIdentifierOutput
    ca_information_access: CaInformationAccessOutput
    subject_key_identifier: str = OutputField(example_values=["9999921f3772284cf53c30f681f14bf6ed035cd9"])


class IssuerOutput(ActionOutput):
    C: str = OutputField(example_values=["US"])
    CN: str = OutputField(example_values=["GTS CA 1C3"])
    O: str = OutputField(example_values=["Google Trust Services LLC"])


class RsaOutput(ActionOutput):
    exponent: str = OutputField(example_values=["010001"])
    key_size: float = OutputField(example_values=[2048])
    modulus: str = OutputField(
        example_values=[
            "999999999f74bea72e3cb68a2a6bb74521f2ee951338a5d9f6a738f98996e2d72295009f544112aa918e99b93ab48f073322711b992887a46211dc853c48e2f22372419c8841221f3dad453289c2331d3b4c881c67660ecc5093bf601130a7aef9f54419ee8e64754c3b07125893af7dabf0bb0f7232d0226605620e12a4416fb22d5c9182394941b218009f6fe2d28d170a1042a0aa726eb9b052a84a57597a4b9a556be00c004ba024bd310d9e4faf17482b137f81b35f470ead7d7d9e418a6653799e9d04f9fd1d4b588809c0e2ac0680f406ba8f4358a143e3cacc7fe792ab9655cc73729dbcd3d7362a7ffe6f903942dc3d588c97917930a9b28b8561c9219b"
        ]
    )


class PublicKeyOutput(ActionOutput):
    algorithm: str = OutputField(example_values=["RSA"])
    rsa: RsaOutput


class SubjectOutput(ActionOutput):
    CN: str = OutputField(example_values=["dns.test"])


class ValidityOutput(ActionOutput):
    not_after: str = OutputField(example_values=["2021-10-04 03:52:55"])
    not_before: str = OutputField(example_values=["2021-07-12 03:52:56"])


class LastHttpsCertificateOutput(ActionOutput):
    cert_signature: CertSignatureOutput
    extensions: ExtensionsOutput
    issuer: IssuerOutput
    public_key: PublicKeyOutput
    serial_number: str = OutputField(example_values=["999999999f93320b7b0a00000000f2c8e9"])
    signature_algorithm: str = OutputField(example_values=["sha256RSA"])
    size: float = OutputField(example_values=[1509])
    subject: SubjectOutput
    thumbprint: str = OutputField(example_values=["999999993948b043f8f258cceebe9eb7a8dd7d06de"])
    thumbprint_sha256: str = OutputField(example_values=["999999e0344c78df40dfcfc2ecd6f83d01b4bcf1def8c548c87691211d904f05"])
    validity: ValidityOutput
    version: str = OutputField(example_values=["V3"])


class TotalVotesOutput(ActionOutput):
    harmless: float = OutputField(example_values=[0])
    malicious: float = OutputField(example_values=[0])


class AttributesOutput(ActionOutput):
    as_owner: str = OutputField(example_values=["Orange"])
    asn: float = OutputField(example_values=[3215])
    continent: str = OutputField(example_values=["EU"])
    country: str = OutputField(example_values=["FR"])
    crowdsourced_context: list[CrowdsourcedContextOutput]
    jarm: str = OutputField(example_values=["29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae"])
    last_analysis_date: float = OutputField(example_values=[1679467461])
    last_analysis_results: list[LastAnalysisResultsOutput]
    last_analysis_stats: LastAnalysisStatsOutput
    last_https_certificate: LastHttpsCertificateOutput
    last_https_certificate_date: float = OutputField(example_values=[1628548284])
    last_modification_date: float = OutputField(example_values=[1612735030])
    network: str = OutputField(example_values=["2.0.0.0/12"])
    regional_internet_registry: str = OutputField(example_values=["RIPE NCC"])
    reputation: float = OutputField(example_values=[0])
    total_votes: TotalVotesOutput
    whois: str = OutputField(
        example_values=[
            "Test data NetRange: 2.0.0.0 - 2.255.255.255 CIDR: 2.0.0.0/8 NetName: 2-RIPE NetHandle: NET-2-0-0-0-1 Parent: () NetType: Allocated to RIPE NCC OriginAS:  Organization: RIPE Network Coordination Centre (RIPE) RegDate: 2009-09-29 Updated: 2009-09-30 Comment: These addresses have been further assigned to users in Comment: the RIPE NCC region. Contact information can be found in Comment: the RIPE database at http://www.ripe.net/whois Ref: https://rdap.arin.net/registry/ip/2.0.0.0 ResourceLink: https://apps.db.ripe.net/search/query.html ResourceLink: whois.ripe.net OrgName: RIPE Network Coordination Centre OrgId: RIPE Address: P.O. Box 10096 City: Amsterdam StateProv:  PostalCode: 1001EB Country: NL RegDate:  Updated: 2013-07-29 Ref: https://rdap.arin.net/registry/entity/RIPE ReferralServer: whois://whois.ripe.net ResourceLink: https://apps.db.ripe.net/search/query.html OrgAbuseHandle: ABUSE3850-ARIN OrgAbuseName: Abuse Contact OrgAbusePhone: +31205354444  OrgAbuseEmail: abuse@ripe.net OrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE3850-ARIN OrgTechHandle: RNO29-ARIN OrgTechName: RIPE NCC Operations OrgTechPhone: +31 20 535 4444  OrgTechEmail: hostmaster@ripe.net OrgTechRef: https://rdap.arin.net/registry/entity/RNO29-ARIN inetnum: 2.3.0.0 - 2.3.7.255 netname: IP2000-ADSL-BAS descr: POP CLE country: FR admin-c: WITR1-RIPE tech-c: WITR1-RIPE status: ASSIGNED PA remarks: for hacking, spamming or security problems send mail to remarks: abuse@orange.fr mnt-by: FT-BRX created: 2017-07-27T08:58:11Z last-modified: 2017-07-27T08:58:11Z source: RIPE role: Wanadoo France Technical Role address: FRANCE TELECOM/SCR address: 48 rue Camille Desmoulins address: 92791 ISSY LES MOULINEAUX CEDEX 9 address: FR phone: +33 1 58 88 50 00 abuse-mailbox: abuse@orange.fr admin-c: BRX1-RIPE tech-c: BRX1-RIPE nic-hdl: WITR1-RIPE mnt-by: FT-BRX created: 2001-12-04T17:57:08Z last-modified: 2013-07-16T14:09:50Z source: RIPE # Filtered route: 2.3.0.0/16 descr: France Telecom Orange origin: AS3215 mnt-by: RAIN-TRANSPAC mnt-by: FT-BRX created: 2012-11-22T09:32:05Z"
        ]
    )
    whois_date: float = OutputField(example_values=[1612735030])


class APILinks(ActionOutput):
    self: str = OutputField(
        cef_types=["url"],
        example_values=["https://www.virustotal.com/api/v3/ip_addresses/2.3.4.5"],
    )


class IpReputationOutput(ActionOutput):
    attributes: AttributesOutput
    id: str = OutputField(cef_types=["ip"], example_values=["2.3.4.5"])
    links: APILinks
    type: str = OutputField(example_values=["ip_address"])


@app.action(description="Queries VirusTotal for IP info", action_type="investigate")
def ip_reputation(params: IpReputationParams, soar: SOARClient, asset: Asset) -> IpReputationOutput:
    raise NotImplementedError()


class UrlReputationParams(Params):
    url: str = Param(description="URL to query", primary=True, cef_types=["url", "domain"])


class DrOutput(ActionOutput):
    Web: str = OutputField(example_values=["e-mail"])


class AlphamountainOutput(ActionOutput):
    ai: str = OutputField(example_values=["File Sharing/Storage, Search Engines/Portals"])


class CategoriesOutput(ActionOutput):
    BitDefender: str = OutputField(example_values=["computersandsoftware"])
    Comodo_Valkyrie_Verdict: str = OutputField(example_values=["media sharing"], alias="Comodo Valkyrie Verdict")
    Dr: DrOutput
    Forcepoint_ThreatSeeker: str = OutputField(example_values=["information technology"], alias="Forcepoint ThreatSeeker")
    Sophos: str = OutputField(example_values=["information technology"])
    Xcitium_Verdict_Cloud: str = OutputField(example_values=["media sharing"], alias="Xcitium Verdict Cloud")
    alphaMountain: AlphamountainOutput


class LastAnalysisResultsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CRDF"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])
    vendor: str = OutputField(example_values=["Symantec"])


class LastAnalysisStatsOutput(ActionOutput):
    harmless: float = OutputField(example_values=[78])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[1])
    timeout: float = OutputField(example_values=[0])
    undetected: float = OutputField(example_values=[8])


class LastHttpResponseCookiesOutput(ActionOutput):
    PROMO: str = OutputField(example_values=["ltv_pid=&ltv_new=1&ltv_ts=1659707757&ltv_sts=1659707757&ltv_c=1"])


class LastHttpResponseHeadersOutput(ActionOutput):
    Accept_CH: str = OutputField(
        example_values=[
            "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64"
        ],
        alias="Accept-CH",
    )
    Accept_Ranges: str = OutputField(example_values=["bytes"], alias="Accept-Ranges")
    Age: str = OutputField(example_values=["0"])
    Alt_Svc: str = OutputField(
        example_values=['h3=":443"; ma=2592000,h3-29=":443"; ma=2592000'],
        alias="Alt-Svc",
    )
    Cache_Control: str = OutputField(example_values=["max-age=3600"], alias="Cache-Control")
    Connection: str = OutputField(example_values=["keep-alive"])
    Content_Encoding: str = OutputField(example_values=["gzip"], alias="Content-Encoding")
    Content_Length: str = OutputField(example_values=["17018"], alias="Content-Length")
    Content_Security_Policy: str = OutputField(example_values=["upgrade-insecure-requests"], alias="Content-Security-Policy")
    Content_Security_Policy_Report_Only: str = OutputField(
        example_values=[
            "object-src 'none';base-uri 'self';script-src 'nonce-foInPZdOHkO_qcMKb-VGOQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp"
        ],
        alias="Content-Security-Policy-Report-Only",
    )
    Content_Type: str = OutputField(example_values=["text/html"], alias="Content-Type")
    Cross_Origin_Opener_Policy: str = OutputField(
        example_values=['same-origin-allow-popups; report-to="gws"'],
        alias="Cross-Origin-Opener-Policy",
    )
    Date: str = OutputField(example_values=["Thu, 09 Mar 2023 15:15:29 GMT"])
    ETag: str = OutputField(example_values=['"128ff-5f63ddbca4199-gzip"'])
    Expect_CT: str = OutputField(example_values=["max-age=31536000, enforce"], alias="Expect-CT")
    Expires: str = OutputField(example_values=["Thu, 09 Mar 2023 16:15:29 GMT"])
    Last_Modified: str = OutputField(example_values=["Mon, 06 Mar 2023 16:33:44 GMT"], alias="Last-Modified")
    Origin_Trial: str = OutputField(
        example_values=[
            "INVALIDzJDKSmEHjzM5ilaa908GuehlLqGb6ezME5lkhelj20qVzfv06zPmQ3LodoeujZuphAolrnhnPA8w4AIAAABfeyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJQZXJtaXNzaW9uc1BvbGljeVVubG9hZCIsImV4cGlyeSI6MTY4NTY2Mzk5OX0=, AvudrjMZqL7335p1KLV2lHo1kxdMeIN0dUI15d0CPz9dovVLCcXk8OAqjho1DX4s6NbHbA/AGobuGvcZv0drGgQAAAB9eyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJCYWNrRm9yd2FyZENhY2hlTm90UmVzdG9yZWRSZWFzb25zIiwiZXhwaXJ5IjoxNjkxNTM5MTk5LCJpc1N1YmRvbWFpbiI6dHJ1ZX0="
        ],
        alias="Origin-Trial",
    )
    P3P: str = OutputField(example_values=['CP="This is not a P3P policy! See g.co/p3phelp for more info."'])
    Permissions_Policy: str = OutputField(example_values=["unload=()"], alias="Permissions-Policy")
    Referrer_Policy: str = OutputField(example_values=["no-referrer-when-downgrade"], alias="Referrer-Policy")
    Report_To: str = OutputField(
        example_values=['{"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]}'],
        alias="Report-To",
    )
    Server: str = OutputField(example_values=["Apache"])
    Set_Cookie: str = OutputField(
        example_values=[
            "INVALID5C560DE64992FF6A94E58729B071419B~YAAQF2IoF7fTtMaGAQAA7gPxxhMyDlfEQK6o6b1VDHh1A4q7gOyp9YKRW51LAjP8LNLyqBS/9X6QK+AWS6ji46AVd+P+YXEK4v2we6cMotyCTXPzSUeR8t7BgwzZdHpKYKw9cguU5OG7DKzGjMPKAYE3AohEOjvVqmHvQZYibzr2FQq0SpEUsTb9TBQHmdKYEMNAmpe7Xlet1DBBK4XAjdRZM0k9C37TCf82HkTnImuoQ/V5guyPnZqiKrlT~1; Domain=.ibm.com; Path=/; Expires=Thu, 09 Mar 2023 17:15:29 GMT; Max-Age=7200; Secure"
        ],
        alias="Set-Cookie",
    )
    Strict_Transport_Security: str = OutputField(example_values=["max-age=31536000"], alias="Strict-Transport-Security")
    Transfer_Encoding: str = OutputField(example_values=["chunked"], alias="Transfer-Encoding")
    Vary: str = OutputField(example_values=["Accept-Encoding"])
    X_Akamai_Transformed: str = OutputField(example_values=["9 16829 0 pmb=mTOE,2"], alias="X-Akamai-Transformed")
    X_Content_Type_Options: str = OutputField(example_values=["nosniff"], alias="X-Content-Type-Options")
    X_Frame_Options: str = OutputField(example_values=["SAMEORIGIN"], alias="X-Frame-Options")
    X_XSS_Protection: str = OutputField(example_values=["1; mode=block"], alias="X-XSS-Protection")
    cache_control: str = OutputField(example_values=["private"], alias="cache-control")
    content_encoding: str = OutputField(example_values=["gzip"], alias="content-encoding")
    content_length: str = OutputField(example_values=["18923"], alias="content-length")
    content_type: str = OutputField(example_values=["text/html; charset=UTF-8"], alias="content-type")
    date: str = OutputField(example_values=["Fri, 05 Aug 2022 13:55:57 GMT"])
    p3p: str = OutputField(
        example_values=[
            'policyref="https://policies.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"'
        ]
    )
    secure_search_bypass: str = OutputField(example_values=["true"])
    server: str = OutputField(example_values=["ATS"])
    set_cookie: str = OutputField(
        example_values=[
            "PROMO=ltv_pid=&ltv_new=1&ltv_ts=1659707757&ltv_sts=1659707757&ltv_c=1; expires=Sat, 05-Aug-2023 13:55:57 GMT; Max-Age=31536000; path=/; domain=.search.yahoo.com"
        ],
        alias="set-cookie",
    )
    vary: str = OutputField(example_values=["Accept-Encoding"])
    x_content_type_options: str = OutputField(example_values=["nosniff"], alias="x-content-type-options")
    x_envoy_upstream_service_time: str = OutputField(example_values=["40"], alias="x-envoy-upstream-service-time")
    x_frame_options: str = OutputField(example_values=["DENY"], alias="x-frame-options")


class TotalVotesOutput(ActionOutput):
    harmless: float = OutputField(example_values=[0])
    malicious: float = OutputField(example_values=[0])


class ScorecardResearchBeaconOutput(ActionOutput):
    id: str = OutputField(example_values=["7241469"])
    timestamp: float = OutputField(example_values=[1627544121])
    url: str = OutputField(
        example_values=["https://sb.scorecardresearch.com/p?c1=2&c2=7241469&c7=https%3A%2F%2Fin.yahoo.com%2F&c5=97684142&cv=2.0&cj=1&c14=-1"]
    )


class YahooDotTagsOutput(ActionOutput):
    timestamp: float = OutputField(example_values=[1627544121])
    url: str = OutputField(example_values=["https://s.yimg.com/rq/darla/4-6-0/js/g-r-min.js"])


class TrackersOutput(ActionOutput):
    ScoreCard_Research_Beacon: list[ScorecardResearchBeaconOutput]
    Yahoo_Dot_Tags: list[YahooDotTagsOutput]


class AttributesOutput(ActionOutput):
    categories: CategoriesOutput
    first_submission_date: float = OutputField(example_values=[1618399455])
    last_analysis_date: float = OutputField(example_values=[1618399455])
    last_analysis_results: list[LastAnalysisResultsOutput]
    last_analysis_stats: LastAnalysisStatsOutput
    last_final_url: str = OutputField(example_values=["https://www.test.com"])
    last_http_response_code: float = OutputField(example_values=[200])
    last_http_response_content_length: float = OutputField(example_values=[154896])
    last_http_response_content_sha256: str = OutputField(example_values=["9999993534b9c77669d1ebc821aed90fb34e31b587a4df32eba708193b25770d9"])
    last_http_response_cookies: LastHttpResponseCookiesOutput
    last_http_response_headers: LastHttpResponseHeadersOutput
    last_modification_date: float = OutputField(example_values=[1618399456])
    last_submission_date: float = OutputField(example_values=[1618399455])
    reputation: float = OutputField(example_values=[0])
    times_submitted: float = OutputField(example_values=[1])
    title: str = OutputField(example_values=["Test"])
    tld: str = OutputField(example_values=["com"])
    total_votes: TotalVotesOutput
    trackers: TrackersOutput
    url: str = OutputField(example_values=["https://www.test.com"])


class APILinks(ActionOutput):
    self: str = OutputField(
        example_values=["https://www.virustotal.com/api/v3/urls/e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"]
    )


class UrlReputationOutput(ActionOutput):
    attributes: AttributesOutput
    id: str = OutputField(example_values=["99999999eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"])
    links: APILinks
    type: str = OutputField(example_values=["url"])


@app.action(
    description="Queries VirusTotal for URL info (run this action after running detonate url)",
    action_type="investigate",
)
def url_reputation(params: UrlReputationParams, soar: SOARClient, asset: Asset) -> UrlReputationOutput:
    raise NotImplementedError()


class DetonateUrlParams(Params):
    url: str = Param(description="URL to detonate", primary=True, cef_types=["url", "domain"])
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class DrOutput(ActionOutput):
    pass


class AlphamountainOutput(ActionOutput):
    pass


class CategoriesOutput(ActionOutput):
    BitDefender: str = OutputField(example_values=["computersandsoftware"])
    Comodo_Valkyrie_Verdict: str = OutputField(example_values=["content server"], alias="Comodo Valkyrie Verdict")
    Dr: DrOutput
    Forcepoint_ThreatSeeker: str = OutputField(example_values=["search engines and portals"], alias="Forcepoint ThreatSeeker")
    Sophos: str = OutputField(example_values=["portal sites"])
    Webroot: str = OutputField(example_values=["Malware Sites"])
    Xcitium_Verdict_Cloud: str = OutputField(example_values=["mobile communications"], alias="Xcitium Verdict Cloud")
    alphaMountain: AlphamountainOutput


class LastAnalysisResultsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CRDF"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])
    vendor: str = OutputField(example_values=["Symantec"])


class LastAnalysisStatsOutput(ActionOutput):
    harmless: float = OutputField(example_values=[78])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[1])
    timeout: float = OutputField(example_values=[0])
    undetected: float = OutputField(example_values=[8])


class LastHttpResponseCookiesOutput(ActionOutput):
    cfduid: str = OutputField(example_values=["dd6592227142b1c1144b4b4ff3ea1a8a91572286127"], alias="__cfduid")


class LastHttpResponseHeadersOutput(ActionOutput):
    Accept_CH: str = OutputField(
        example_values=[
            "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64"
        ],
        alias="Accept-CH",
    )
    Access_Control_Allow_Origin: str = OutputField(example_values=["*"], alias="Access-Control-Allow-Origin")
    Age: str = OutputField(example_values=["0"])
    Alt_Svc: str = OutputField(
        example_values=['h3=":443"; ma=2592000,h3-29=":443"; ma=2592000'],
        alias="Alt-Svc",
    )
    CF_Cache_Status: str = OutputField(example_values=["DYNAMIC"], alias="CF-Cache-Status")
    CF_RAY: str = OutputField(example_values=["7d1c90339ff22bb3-ORD"], alias="CF-RAY")
    Cache_Control: str = OutputField(example_values=["no-store, no-cache, max-age=0, private"], alias="Cache-Control")
    Connection: str = OutputField(example_values=["keep-alive"])
    Content_Encoding: str = OutputField(example_values=["gzip"], alias="Content-Encoding")
    Content_Security_Policy: str = OutputField(
        example_values=[
            "frame-ancestors 'self' https://*.builtbygirls.com https://*.rivals.com https://*.engadget.com https://*.intheknow.com https://*.autoblog.com https://*.techcrunch.com https://*.yahoo.com https://*.aol.com https://*.huffingtonpost.com https://*.oath.com https://*.search.yahoo.com https://*.pnr.ouryahoo.com https://pnr.ouryahoo.com https://*.search.aol.com https://*.search.huffpost.com https://*.onesearch.com https://*.verizonmedia.com https://*.publishing.oath.com https://*.autoblog.com; sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox allow-presentation; report-uri https://csp.yahoo.com/beacon/csp?src=ats&site=frontpage&region=US&lang=en-US&device=smartphone&yrid=7h2ptmphvv9rl&partner=;"
        ],
        alias="Content-Security-Policy",
    )
    Content_Security_Policy_Report_Only: str = OutputField(
        example_values=[
            "object-src 'none';base-uri 'self';script-src 'nonce-qGMKc53CjVAFzzZ8RUEtnA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp"
        ],
        alias="Content-Security-Policy-Report-Only",
    )
    Content_Type: str = OutputField(example_values=["text/html; charset=UTF-8"], alias="Content-Type")
    Cross_Origin_Opener_Policy: str = OutputField(
        example_values=['same-origin-allow-popups; report-to="gws"'],
        alias="Cross-Origin-Opener-Policy",
    )
    Cross_Origin_Opener_Policy_Report_Only: str = OutputField(
        example_values=['same-origin; report-to="AccountsSignInUi"'],
        alias="Cross-Origin-Opener-Policy-Report-Only",
    )
    Cross_Origin_Resource_Policy: str = OutputField(example_values=["same-site"], alias="Cross-Origin-Resource-Policy")
    Date: str = OutputField(example_values=["Tue, 21 Mar 2023 12:43:43 GMT"])
    ETag: str = OutputField(example_values=['"7cVmZQ"'])
    Expires: str = OutputField(example_values=["-1"])
    Link: str = OutputField(
        example_values=[
            '<https://hii.com/wp-json/>; rel="https://api.w.org/", <https://hii.com/wp-json/wp/v2/pages/8298>; rel="alternate"; type="application/json", <https://hii.com/>; rel=shortlink'
        ]
    )
    Origin_Trial: str = OutputField(
        example_values=[
            "999999999DKSmEHjzM5ilaa908GuehlLqGb6ezME5lkhelj20qVzfv06zPmQ3LodoeujZuphAolrnhnPA8w4AIAAABfeyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJQZXJtaXNzaW9uc1BvbGljeVVubG9hZCIsImV4cGlyeSI6MTY4NTY2Mzk5OX0=, AvudrjMZqL7335p1KLV2lHo1kxdMeIN0dUI15d0CPz9dovVLCcXk8OAqjho1DX4s6NbHbA/AGobuGvcZv0drGgQAAAB9eyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJCYWNrRm9yd2FyZENhY2hlTm90UmVzdG9yZWRSZWFzb25zIiwiZXhwaXJ5IjoxNjkxNTM5MTk5LCJpc1N1YmRvbWFpbiI6dHJ1ZX0="
        ],
        alias="Origin-Trial",
    )
    P3P: str = OutputField(example_values=['CP="This is not a P3P policy! See g.co/p3phelp for more info."'])
    Permissions_Policy: str = OutputField(example_values=["unload=()"], alias="Permissions-Policy")
    Pragma: str = OutputField(example_values=["no-cache"])
    Report_To: str = OutputField(
        example_values=['{"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]}'],
        alias="Report-To",
    )
    Server: str = OutputField(example_values=["gws"])
    Set_Cookie: str = OutputField(
        example_values=[
            "1P_JAR=2023-03-21-12; expires=Thu, 20-Apr-2023 12:43:43 GMT; path=/; domain=.google.com; Secure; SameSite=none, NID=511=uSBKYmXpnAMHRYvebOLMDNVKuXQVvO8Q-3eHs2Zjj6RhQwWNjU-j04Ysj_9pykK6S60UsbRbhRODW4_ywypZCL6j8dpbVFNJR5Ig-zy7qkEka26Oq-DpJdeV4XPWPVmg-dB6AXJJA6goK0QcMAiqPZK7OanyPrB1fY06uc9zreA; expires=Wed, 20-Sep-2023 12:43:43 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none"
        ],
        alias="Set-Cookie",
    )
    Strict_Transport_Security: str = OutputField(example_values=["max-age=31536000"], alias="Strict-Transport-Security")
    Transfer_Encoding: str = OutputField(example_values=["chunked"], alias="Transfer-Encoding")
    Vary: str = OutputField(example_values=["Accept-Encoding, Accept-Encoding, Accept-Encoding"])
    X_Cache: str = OutputField(example_values=["HIT: 9"], alias="X-Cache")
    X_Cache_Group: str = OutputField(example_values=["bot-mobile"], alias="X-Cache-Group")
    X_Cacheable: str = OutputField(example_values=["bot"], alias="X-Cacheable")
    X_Cloud_Trace_Context: str = OutputField(
        example_values=["9999999fda4db85ed68e4e34e7aefac6"],
        alias="X-Cloud-Trace-Context",
    )
    X_Content_Type_Options: str = OutputField(example_values=["nosniff"], alias="X-Content-Type-Options")
    X_Frame_Options: str = OutputField(example_values=["SAMEORIGIN"], alias="X-Frame-Options")
    X_Powered_By: str = OutputField(example_values=["WP Engine"], alias="X-Powered-By")
    X_XSS_Protection: str = OutputField(example_values=["0"], alias="X-XSS-Protection")
    access_control_allow_origin: str = OutputField(example_values=["*"], alias="access-control-allow-origin")
    alt_svc: str = OutputField(example_values=['h3=":443"; ma=86400'], alias="alt-svc")
    cf_ray: str = OutputField(example_values=["52cedb66e8b6c53c-ORD"], alias="cf-ray")
    connection: str = OutputField(example_values=["keep-alive"])
    content_encoding: str = OutputField(example_values=["gzip"], alias="content-encoding")
    content_length: str = OutputField(example_values=["15"], alias="content-length")
    content_type: str = OutputField(example_values=["text/html; charset=utf-8"], alias="content-type")
    date: str = OutputField(example_values=["Wed, 01 Mar 2023 19:28:53 GMT"])
    expect_ct: str = OutputField(
        example_values=['max-age=31536000, report-uri="http://csp.yahoo.com/beacon/csp?src=yahoocom-expect-ct-report-only"'],
        alias="expect-ct",
    )
    keep_alive: str = OutputField(example_values=["timeout=5, max=100"], alias="keep-alive")
    referrer_policy: str = OutputField(example_values=["no-referrer-when-downgrade"], alias="referrer-policy")
    server: str = OutputField(example_values=["ATS"])
    set_cookie: str = OutputField(
        example_values=[
            "__cfduid=99999997142b1c1144b4b4ff3ea1a8a91572286127; expires=Tue, 27-Oct-20 18:08:47 GMT; path=/; domain=.ipinfo.in; HttpOnly; Secure"
        ],
        alias="set-cookie",
    )
    strict_transport_security: str = OutputField(example_values=["max-age=31536000"], alias="strict-transport-security")
    vary: str = OutputField(example_values=["User-Agent"])
    x_content_type_options: str = OutputField(example_values=["nosniff"], alias="x-content-type-options")
    x_envoy_upstream_service_time: str = OutputField(example_values=["54"], alias="x-envoy-upstream-service-time")
    x_frame_options: str = OutputField(example_values=["SAMEORIGIN"], alias="x-frame-options")
    x_powered_by: str = OutputField(example_values=["PHP/7.4.29, PleskLin"], alias="x-powered-by")
    x_ua_compatible: str = OutputField(example_values=["IE=edge"], alias="x-ua-compatible")
    x_xss_protection: str = OutputField(example_values=["1; mode=block"], alias="x-xss-protection")


class TotalVotesOutput(ActionOutput):
    harmless: float = OutputField(example_values=[0])
    malicious: float = OutputField(example_values=[0])


class DoubleclickOutput(ActionOutput):
    timestamp: float = OutputField(example_values=[1664533059])
    url: str


class GooglePublisherTagsOutput(ActionOutput):
    timestamp: float = OutputField(example_values=[1677698931])
    url: str = OutputField(example_values=["https://securepubads.g.doubleclick.net/tag/js/gpt.js"])


class GoogleTagManagerOutput(ActionOutput):
    id: str = OutputField(example_values=["G-PTR82E305T"])
    timestamp: float = OutputField(example_values=[1685843825])
    url: str = OutputField(example_values=["https://www.googletagmanager.com/gtag/js?id=G-PTR82E305T"])


class ScorecardResearchBeaconOutput(ActionOutput):
    id: str = OutputField(example_values=["7241469"])
    timestamp: float = OutputField(example_values=[1677698931])
    url: str = OutputField(
        example_values=["https://sb.scorecardresearch.com/p?c1=2&c2=7241469&c5=1197228339&c7=https%3A%2F%2Fwww.yahoo.com%2F&c14=-1"]
    )


class YahooDotTagsOutput(ActionOutput):
    timestamp: float = OutputField(example_values=[1677698931])
    url: str = OutputField(example_values=["https://s.yimg.com/ss/rapid-3.53.38.js"])


class TrackersOutput(ActionOutput):
    Doubleclick: list[DoubleclickOutput]
    Google_Publisher_Tags: list[GooglePublisherTagsOutput]
    Google_Tag_Manager: list[GoogleTagManagerOutput]
    ScoreCard_Research_Beacon: list[ScorecardResearchBeaconOutput]
    Yahoo_Dot_Tags: list[YahooDotTagsOutput]


class AttributesOutput(ActionOutput):
    date: float = OutputField(example_values=[1613648861])
    # results: ResultsOutput
    # stats: StatsOutput
    status: str = OutputField(example_values=["completed"])


class n0XsiF33DOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["0xSI_f33d"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class AdminuslabsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ADMINUSLabs"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Aicc_Monitorapp_Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["AICC (MONITORAPP)"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AbusixOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Abusix"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AcronisOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Acronis"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AlienvaultOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["AlienVault"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AlphasocOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["AlphaSOC"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class Antiy_AvlOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Antiy-AVL"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ArcsightThreatIntelligenceOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["ArcSight Threat Intelligence"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class ArtistsAgainst419Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Artists Against 419"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AutoshunOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["AutoShun"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class AviraOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Avira"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AiPrecrimeOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Bfore.Ai PreCrime"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BforeOutput(ActionOutput):
    Ai_PreCrime: AiPrecrimeOutput


class BitdefenderOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["BitDefender"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BkavOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Bkav"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class BlocklistOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["BlockList"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BluelivOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Blueliv"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CinsArmyOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CINS Army"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CmcThreatIntelligenceOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CMC Threat Intelligence"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CrdfOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CRDF"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CertegoOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Certego"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ChongLuaDaoOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Chong Lua Dao"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Cluster25Output(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Cluster25"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class CriminalIpOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Criminal IP"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class CrowdsecOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["CrowdSec"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class CyradarOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CyRadar"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CyanOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Cyan"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class CybleOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Cyble"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Dns8Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["DNS8"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class WebOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Dr.Web"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EsetOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ESET"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EstsecurityOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ESTsecurity"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EmergingthreatsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["EmergingThreats"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EmsisoftOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Emsisoft"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class FeodoTrackerOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Feodo Tracker"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ForcepointThreatseekerOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Forcepoint ThreatSeeker"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class FortinetOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Fortinet"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class G_DataOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["G-Data"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class GoogleSafebrowsingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Google Safebrowsing"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class GreensnowOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["GreenSnow"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class HeimdalSecurityOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Heimdal Security"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class IpsumOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["IPsum"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class JuniperNetworksOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Juniper Networks"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class K7AntivirusOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["K7AntiVirus"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class KasperskyOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Kaspersky"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class LionicOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Lionic"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class LumuOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Lumu"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class MalwarepatrolOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["MalwarePatrol"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwaredOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Malwared"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class NetcraftOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Netcraft"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class OpenphishOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["OpenPhish"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PrebytesOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["PREBYTES"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PhishfortOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["PhishFort"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class PhishlabsOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["PhishLabs"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class PhishingDatabaseOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Phishing Database"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PhishtankOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Phishtank"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PrecisionsecOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["PrecisionSec"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class QuickHealOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Quick Heal"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class QutteraOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Quttera"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class RisingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Rising"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class OrgOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["SCUMWARE.org"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ScumwareOutput(ActionOutput):
    org: OrgOutput


class SocradarOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["SOCRadar"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class SafetoopenOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["SafeToOpen"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class SangforOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Sangfor"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ScantitanOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Scantitan"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SeclookupOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Seclookup"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SecurebrainOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["SecureBrain"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SnortIpSampleListOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Snort IP sample list"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SophosOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Sophos"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Spam404Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Spam404"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class StopforumspamOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["StopForumSpam"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SucuriSitecheckOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Sucuri SiteCheck"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ThreathiveOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ThreatHive"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ThreatsourcingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Threatsourcing"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class TrustwaveOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Trustwave"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class UrlqueryOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["URLQuery"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class UrlhausOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["URLhaus"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class VipreOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["VIPRE"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class VxVaultOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["VX Vault"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ViettelThreatIntelligenceOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Viettel Threat Intelligence"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ViribackOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ViriBack"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class WebrootOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Webroot"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class XcitiumVerdictCloudOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Xcitium Verdict Cloud"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class YandexSafebrowsingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Yandex Safebrowsing"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ZerocertOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ZeroCERT"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AiOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["alphaMountain.ai"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CcOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["benkow.cc"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BenkowOutput(ActionOutput):
    cc: CcOutput


class MeOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["desenmascara.me"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class DesenmascaraOutput(ActionOutput):
    me: MeOutput


class ComUrlCheckerOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["malwares.com URL checker"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwaresOutput(ActionOutput):
    com_URL_checker: ComUrlCheckerOutput


class SecurolyticsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["securolytics"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ResultsOutput(ActionOutput):
    n0xSI_f33d: n0XsiF33DOutput
    ADMINUSLabs: AdminuslabsOutput
    AICC__MONITORAPP_: Aicc_Monitorapp_Output
    Abusix: AbusixOutput
    Acronis: AcronisOutput
    AlienVault: AlienvaultOutput
    AlphaSOC: AlphasocOutput
    Antiy_AVL: Antiy_AvlOutput
    ArcSight_Threat_Intelligence: ArcsightThreatIntelligenceOutput
    Artists_Against_419: ArtistsAgainst419Output
    AutoShun: AutoshunOutput
    Avira: AviraOutput
    Bfore: BforeOutput
    BitDefender: BitdefenderOutput
    Bkav: BkavOutput
    BlockList: BlocklistOutput
    Blueliv: BluelivOutput
    CINS_Army: CinsArmyOutput
    CMC_Threat_Intelligence: CmcThreatIntelligenceOutput
    CRDF: CrdfOutput
    Certego: CertegoOutput
    Chong_Lua_Dao: ChongLuaDaoOutput
    Cluster25: Cluster25Output
    Criminal_IP: CriminalIpOutput
    CrowdSec: CrowdsecOutput
    CyRadar: CyradarOutput
    Cyan: CyanOutput
    Cyble: CybleOutput
    DNS8: Dns8Output
    Dr: DrOutput
    ESET: EsetOutput
    ESTsecurity: EstsecurityOutput
    EmergingThreats: EmergingthreatsOutput
    Emsisoft: EmsisoftOutput
    Feodo_Tracker: FeodoTrackerOutput
    Forcepoint_ThreatSeeker: ForcepointThreatseekerOutput
    Fortinet: FortinetOutput
    G_Data: G_DataOutput
    Google_Safebrowsing: GoogleSafebrowsingOutput
    GreenSnow: GreensnowOutput
    Heimdal_Security: HeimdalSecurityOutput
    IPsum: IpsumOutput
    Juniper_Networks: JuniperNetworksOutput
    K7AntiVirus: K7AntivirusOutput
    Kaspersky: KasperskyOutput
    Lionic: LionicOutput
    Lumu: LumuOutput
    MalwarePatrol: MalwarepatrolOutput
    Malwared: MalwaredOutput
    Netcraft: NetcraftOutput
    OpenPhish: OpenphishOutput
    PREBYTES: PrebytesOutput
    PhishFort: PhishfortOutput
    PhishLabs: PhishlabsOutput
    Phishing_Database: PhishingDatabaseOutput
    Phishtank: PhishtankOutput
    PrecisionSec: PrecisionsecOutput
    Quick_Heal: QuickHealOutput
    Quttera: QutteraOutput
    Rising: RisingOutput
    SCUMWARE: ScumwareOutput
    SOCRadar: SocradarOutput
    SafeToOpen: SafetoopenOutput
    Sangfor: SangforOutput
    Scantitan: ScantitanOutput
    Seclookup: SeclookupOutput
    SecureBrain: SecurebrainOutput
    Snort_IP_sample_list: SnortIpSampleListOutput
    Sophos: SophosOutput
    Spam404: Spam404Output
    StopForumSpam: StopforumspamOutput
    Sucuri_SiteCheck: SucuriSitecheckOutput
    ThreatHive: ThreathiveOutput
    Threatsourcing: ThreatsourcingOutput
    Trustwave: TrustwaveOutput
    URLQuery: UrlqueryOutput
    URLhaus: UrlhausOutput
    VIPRE: VipreOutput
    VX_Vault: VxVaultOutput
    Viettel_Threat_Intelligence: ViettelThreatIntelligenceOutput
    ViriBack: ViribackOutput
    Webroot: WebrootOutput
    Xcitium_Verdict_Cloud: XcitiumVerdictCloudOutput
    Yandex_Safebrowsing: YandexSafebrowsingOutput
    ZeroCERT: ZerocertOutput
    alphaMountain: AlphamountainOutput
    benkow: BenkowOutput
    desenmascara: DesenmascaraOutput
    malwares: MalwaresOutput
    securolytics: SecurolyticsOutput


class StatsOutput(ActionOutput):
    harmless: float = OutputField(example_values=[76])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[0])
    timeout: float = OutputField(example_values=[0])
    undetected: float = OutputField(example_values=[7])


class APILinks(ActionOutput):
    self: str = OutputField(
        example_values=["https://www.virustotal.com/api/v3/urls/e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"]
    )


class DataOutput(ActionOutput):
    attributes: AttributesOutput
    id: str = OutputField(
        cef_types=["virustotal scan id"],
        example_values=["u-e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761-1613648861"],
    )
    links: APILinks
    type: str = OutputField(example_values=["analysis"])


class UrlInfoOutput(ActionOutput):
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=["e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761"],
    )
    url: str = OutputField(cef_types=["url"], example_values=["https://www.123test.com/"])


class MetaOutput(ActionOutput):
    url_info: UrlInfoOutput


class DetonateUrlOutput(ActionOutput):
    attributes: AttributesOutput
    data: DataOutput
    id: str = OutputField(example_values=["e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063"])
    links: APILinks
    meta: MetaOutput
    type: str = OutputField(example_values=["url"])


@app.action(
    description="Load a URL to Virus Total and retrieve analysis results",
    action_type="investigate",
    verbose="<b>detonate url</b> will send a URL to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given URL has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def detonate_url(params: DetonateUrlParams, soar: SOARClient, asset: Asset) -> DetonateUrlOutput:
    raise NotImplementedError()


class DetonateFileParams(Params):
    vault_id: str = Param(
        description="The Vault ID of the file to scan",
        primary=True,
        cef_types=["vault id", "sha1"],
    )
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class RiskindicatorOutput(ActionOutput):
    APK: list[float] = OutputField(example_values=[1])
    PERM: list[float] = OutputField(example_values=[1])


class CertificateOutput(ActionOutput):
    Issuer: list[str] = OutputField(example_values=["C:US, CN:Android Debug, O:Android"])
    Subject: list[str] = OutputField(example_values=["US"])
    serialnumber: str = OutputField(example_values=["6f20b2e6"])
    thumbprint: str = OutputField(example_values=["7bd81368b868225bde96fc1a3fee59a8ea06296a"])
    validfrom: str = OutputField(example_values=["2016-01-27 08:46:16"])
    validto: str = OutputField(example_values=["2046-01-19 08:46:16"])


class PermissionOutput(ActionOutput):
    full_description: str = OutputField(example_values=["Allows an application to create network sockets."])
    permission_type: str = OutputField(example_values=["dangerous"])
    short_description: str = OutputField(example_values=["full Internet access"])


class AndroidOutput(ActionOutput):
    pass


class TestOutput(ActionOutput):
    full_description: str = OutputField(example_values=["Unknown permission from android reference"])
    permission_type: str = OutputField(example_values=["normal"])
    short_description: str = OutputField(example_values=["Unknown permission from android reference"])


class AnalyzerOutput(ActionOutput):
    test: list[TestOutput]


class IbmOutput(ActionOutput):
    android: AndroidOutput


class ComOutput(ActionOutput):
    ibm: IbmOutput


class PermissionDetailsOutput(ActionOutput):
    android: AndroidOutput
    com: ComOutput


class AndroguardOutput(ActionOutput):
    AndroguardVersion: str = OutputField(example_values=["3.0-dev"])
    AndroidApplication: float = OutputField(example_values=[1])
    AndroidApplicationError: bool = OutputField(example_values=[False])
    AndroidApplicationInfo: str = OutputField(example_values=["APK"])
    AndroidVersionCode: str = OutputField(example_values=["1"])
    AndroidVersionName: str = OutputField(example_values=["1.0"])
    MinSdkVersion: str = OutputField(example_values=["11"])
    Package: str = OutputField(example_values=["com.ibm.android.analyzer.test"])
    RiskIndicator: RiskindicatorOutput
    TargetSdkVersion: str = OutputField(example_values=["11"])
    VTAndroidInfo: float = OutputField(example_values=[1.41])
    certificate: CertificateOutput
    main_activity: str = OutputField(example_values=["com.ibm.android.analyzer.test.xas.CAS"])
    permission_details: PermissionDetailsOutput


class BundleInfoOutput(ActionOutput):
    extensions: list[float] = OutputField(example_values=[1])
    file_types: list[float] = OutputField(example_values=[1])
    highest_datetime: str = OutputField(example_values=["2019-01-03 12:33:40"])
    lowest_datetime: str = OutputField(example_values=["2019-01-03 12:33:40"])
    num_children: float = OutputField(example_values=[1])
    type: str = OutputField(example_values=["ZIP"])
    uncompressed_size: float = OutputField(example_values=[481])


class CrowdsourcedIdsResultsOutput(ActionOutput):
    alert_severity: str = OutputField(example_values=["medium"])
    rule_category: str = OutputField(example_values=["Potentially Bad Traffic"])
    rule_id: str = OutputField(example_values=["1:2027865"])
    rule_msg: str = OutputField(example_values=["ET INFO Observed DNS Query to .cloud TLD"])
    rule_raw: str = OutputField(
        example_values=[
            'alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns.query; content:".cloud"; nocase; endswith; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027865; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2019_08_13, deployment Perimeter, former_category INFO, signature_severity Major, updated_at 2020_09_17;)'
        ]
    )
    rule_source: str = OutputField(example_values=["Proofpoint Emerging Threats Open"])
    rule_url: str = OutputField(example_values=["https://rules.emergingthreats.net/"])


class IframesOutput(ActionOutput):
    attributes: list[str] = OutputField(example_values=["./test_html_files/list.html"])


class AttributesOutput(ActionOutput):
    date: float = OutputField(example_values=[1613651763])
    results: ResultsOutput
    stats: StatsOutput
    status: str = OutputField(example_values=["completed"])


class ScriptsOutput(ActionOutput):
    attributes: AttributesOutput


class HtmlInfoOutput(ActionOutput):
    iframes: list[IframesOutput]
    scripts: list[ScriptsOutput]


class LastAnalysisResultsOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["CMC"])
    engine_update: str = OutputField(example_values=["20210218"])
    engine_version: str = OutputField(example_values=["2.10.2019.1"])
    method: str = OutputField(example_values=["blacklist"])
    result: str
    vendor: str = OutputField(example_values=["Symantec"])


class LastAnalysisStatsOutput(ActionOutput):
    confirmed_timeout: float = OutputField(example_values=[0], alias="confirmed-timeout")
    failure: float = OutputField(example_values=[0])
    harmless: float = OutputField(example_values=[0])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[0])
    timeout: float = OutputField(example_values=[0])
    type_unsupported: float = OutputField(example_values=[16], alias="type-unsupported")
    undetected: float = OutputField(example_values=[59])


class PackersOutput(ActionOutput):
    F_PROT: str = OutputField(example_values=["appended, docwrite"], alias="F-PROT")


class PdfInfoOutput(ActionOutput):
    acroform: float
    autoaction: float
    embedded_file: float
    encrypted: float
    flash: float
    header: str = OutputField(example_values=["%PDF-1.5"])
    javascript: float
    jbig2_compression: float
    js: float
    num_endobj: float = OutputField(example_values=[29])
    num_endstream: float = OutputField(example_values=[28])
    num_launch_actions: float
    num_obj: float = OutputField(example_values=[29])
    num_object_streams: float = OutputField(example_values=[1])
    num_pages: float
    num_stream: float = OutputField(example_values=[28])
    openaction: float
    startxref: float = OutputField(example_values=[1])
    suspicious_colors: float
    trailer: float
    xfa: float
    xref: float


class ImportListOutput(ActionOutput):
    library_name: str = OutputField(example_values=["MSVCP60.dll"])


class ResourceDetailsOutput(ActionOutput):
    chi2: float = OutputField(example_values=[33203.078125])
    entropy: float = OutputField(example_values=[1.802635908126831])
    filetype: str = OutputField(example_values=["Data"])
    lang: str = OutputField(example_values=["CHINESE SIMPLIFIED"])
    sha256: str = OutputField(example_values=["9999999999f0f912228ae647d10e15a014b8ce40dd164fa30290913227d"])
    type: str = OutputField(example_values=["RT_CURSOR"])


class ResourceLangsOutput(ActionOutput):
    CHINESE_SIMPLIFIED: float = OutputField(example_values=[8], alias="CHINESE SIMPLIFIED")


class ResourceTypesOutput(ActionOutput):
    RT_BITMAP: float = OutputField(example_values=[4])
    RT_CURSOR: float = OutputField(example_values=[1])
    RT_GROUP_CURSOR: float = OutputField(example_values=[1])
    RT_MENU: float = OutputField(example_values=[1])
    RT_VERSION: float = OutputField(example_values=[1])


class SectionsOutput(ActionOutput):
    chi2: float = OutputField(example_values=[672207.13])
    entropy: float = OutputField(example_values=[6.46])
    flags: str = OutputField(example_values=["rx"])
    md5: str = OutputField(example_values=["999999999982ea3987560f91ce29f946f4"])
    name: str = OutputField(example_values=[".text"])
    raw_size: float = OutputField(example_values=[90112])
    virtual_address: float = OutputField(example_values=[4096])
    virtual_size: float = OutputField(example_values=[90112])


class PeInfoOutput(ActionOutput):
    entry_point: float = OutputField(example_values=[176128])
    imphash: str = OutputField(example_values=["6bff2c73afd9249c4261ecfba6ff33c3"])
    import_list: list[ImportListOutput]
    machine_type: float = OutputField(example_values=[332])
    overlay: list[str] = OutputField(example_values=["xyz"])
    resource_details: list[ResourceDetailsOutput]
    resource_langs: ResourceLangsOutput
    resource_types: ResourceTypesOutput
    rich_pe_header_hash: str = OutputField(example_values=["9999999999167a185aba138b2846e0b906"])
    sections: list[SectionsOutput]
    timestamp: float = OutputField(example_values=[1259933759])


class PopularThreatCategoryOutput(ActionOutput):
    count: float = OutputField(example_values=[16])
    value: str = OutputField(example_values=["virus"])


class PopularThreatNameOutput(ActionOutput):
    count: float = OutputField(example_values=[32])
    value: str = OutputField(example_values=["parite"])


class PopularThreatClassificationOutput(ActionOutput):
    popular_threat_category: list[PopularThreatCategoryOutput]
    popular_threat_name: list[PopularThreatNameOutput]
    suggested_threat_label: str = OutputField(example_values=["virus.parite/pate"])


class SandboxVerdictsOutput(ActionOutput):
    Lastline: list[str] = OutputField(example_values=["xyz"])
    Tencent_HABO: list[str] = OutputField(example_values=["xyz"], alias="Tencent HABO")


class TotalVotesOutput(ActionOutput):
    harmless: float = OutputField(example_values=[0])
    malicious: float = OutputField(example_values=[0])


class TridOutput(ActionOutput):
    file_type: str = OutputField(example_values=["Unix-like shebang (var.1) (gen)"])
    probability: float = OutputField(example_values=[100])


class AlyacOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["ALYac"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.1.3.1"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ApexOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["APEX"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["6.396"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class AvgOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["AVG"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["22.11.7701.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class AcronisOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Acronis"])
    engine_update: str = OutputField(example_values=["20230219"])
    engine_version: str = OutputField(example_values=["1.2.0.114"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Ahnlab_V3Output(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["AhnLab-V3"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["3.23.1.10344"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class AlibabaOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Alibaba"])
    engine_update: str = OutputField(example_values=["20190527"])
    engine_version: str = OutputField(example_values=["0.3.0.5"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Antiy_AvlOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Antiy-AVL"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["3.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ArcabitOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Arcabit"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["2022.0.0.18"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Avast_MobileOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Avast-Mobile"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["230312-00"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class AvastOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Avast"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["22.11.7701.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class AviraOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Avira"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["8.3.3.16"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class BaiduOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Baidu"])
    engine_update: str = OutputField(example_values=["20190318"])
    engine_version: str = OutputField(example_values=["1.0.0.2"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class BitdefenderOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["BitDefender"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["7.2"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class BitdefenderfalxOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["BitDefenderFalx"])
    engine_update: str = OutputField(example_values=["20230203"])
    engine_version: str = OutputField(example_values=["2.0.936"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class BitdefenderthetaOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["BitDefenderTheta"])
    engine_update: str = OutputField(example_values=["20230228"])
    engine_version: str = OutputField(example_values=["7.2.37796.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class BkavOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Bkav"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.3.0.9899"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Cat_QuickhealOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["CAT-QuickHeal"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["22.00"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class CmcOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["CMC"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["2.4.2022.1"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ClamavOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["ClamAV"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["1.0.1.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class CrowdstrikeOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["CrowdStrike"])
    engine_update: str = OutputField(example_values=["20220812"])
    engine_version: str = OutputField(example_values=["1.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class CylanceOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Cylance"])
    engine_update: str = OutputField(example_values=["20230302"])
    engine_version: str = OutputField(example_values=["2.0.0.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class CynetOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Cynet"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["4.0.0.27"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class CyrenOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Cyren"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["6.5.1.2"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class DrwebOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["DrWeb"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["7.0.59.12300"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Eset_Nod32Output(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["ESET-NOD32"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["26892"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ElasticOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Elastic"])
    engine_update: str = OutputField(example_values=["20230302"])
    engine_version: str = OutputField(example_values=["4.0.80"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class EmsisoftOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Emsisoft"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["2022.6.0.32461"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class F_SecureOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["F-Secure"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["18.10.1137.128"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class FireeyeOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["FireEye"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["35.24.1.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class FortinetOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Fortinet"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["6.4.258.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class GdataOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["GData"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["A:25.35442B:27.30944"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class GoogleOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Google"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1678687243"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class GridinsoftOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Gridinsoft"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.0.110.174"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class IkarusOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Ikarus"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["6.0.33.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class JiangminOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Jiangmin"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["16.0.100"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class K7AntivirusOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["K7AntiVirus"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["12.72.47258"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class K7GwOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["K7GW"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["12.72.47258"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class KasperskyOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Kaspersky"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["22.0.1.28"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class LionicOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Lionic"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["7.5"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class MaxOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["MAX"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["2023.1.4.1"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class MalwarebytesOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Malwarebytes"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["4.4.4.52"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class MaxsecureOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["MaxSecure"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["1.0.0.1"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Mcafee_Gw_EditionOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["McAfee-GW-Edition"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["v2021.2.0+4045"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class McafeeOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["McAfee"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["6.0.6.653"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Microworld_EscanOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["MicroWorld-eScan"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["14.0.409.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class MicrosoftOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Microsoft"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.1.20000.2"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Nano_AntivirusOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["NANO-Antivirus"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.0.146.25743"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class PaloaltoOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Paloalto"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["0.9.0.1003"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class PandaOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Panda"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["4.6.4.2"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class RisingOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Rising"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["25.0.0.27"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class SuperantispywareOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["SUPERAntiSpyware"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["5.6.0.1032"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class SangforOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Sangfor"])
    engine_update: str = OutputField(example_values=["20230309"])
    engine_version: str = OutputField(example_values=["2.23.0.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class SentineloneOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["SentinelOne"])
    engine_update: str = OutputField(example_values=["20230216"])
    engine_version: str = OutputField(example_values=["23.1.3.2"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class SophosOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Sophos"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["2.1.2.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class SymantecOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Symantec"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["1.19.0.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class SymantecmobileinsightOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["SymantecMobileInsight"])
    engine_update: str = OutputField(example_values=["20230119"])
    engine_version: str = OutputField(example_values=["2.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class TachyonOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["TACHYON"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["2023-03-13.01"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class TencentOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Tencent"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.0.0.1"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class TrapmineOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Trapmine"])
    engine_update: str = OutputField(example_values=["20230103"])
    engine_version: str = OutputField(example_values=["4.0.10.141"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Trendmicro_HousecallOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["TrendMicro-HouseCall"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["10.0.0.1040"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class TrendmicroOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["TrendMicro"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["11.0.0.1006"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class TrustlookOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Trustlook"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class Vba32Output(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["VBA32"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["5.0.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class VipreOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["VIPRE"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["6.0.0.35"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class VirobotOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["ViRobot"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["2014.3.20.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ViritOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["VirIT"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["9.5.405"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class WebrootOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["Webroot"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.0.0.403"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class XcitiumOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Xcitium"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["35481"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class YandexOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Yandex"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["5.5.2.24"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ZillyaOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Zillya"])
    engine_update: str = OutputField(example_values=["20230310"])
    engine_version: str = OutputField(example_values=["2.0.0.4829"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ZonealarmOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["ZoneAlarm"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["1.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ZonerOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Zoner"])
    engine_update: str = OutputField(example_values=["20230312"])
    engine_version: str = OutputField(example_values=["2.2.2.0"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class TehtrisOutput(ActionOutput):
    category: str = OutputField(example_values=["type-unsupported"])
    engine_name: str = OutputField(example_values=["tehtris"])
    engine_update: str = OutputField(example_values=["20230313"])
    engine_version: str = OutputField(example_values=["v0.1.4"])
    method: str = OutputField(example_values=["blacklist"])
    result: str


class ResultsOutput(ActionOutput):
    ALYac: AlyacOutput
    APEX: ApexOutput
    AVG: AvgOutput
    Acronis: AcronisOutput
    AhnLab_V3: Ahnlab_V3Output
    Alibaba: AlibabaOutput
    Antiy_AVL: Antiy_AvlOutput
    Arcabit: ArcabitOutput
    Avast_Mobile: Avast_MobileOutput
    Avast: AvastOutput
    Avira: AviraOutput
    Baidu: BaiduOutput
    BitDefender: BitdefenderOutput
    BitDefenderFalx: BitdefenderfalxOutput
    BitDefenderTheta: BitdefenderthetaOutput
    Bkav: BkavOutput
    CAT_QuickHeal: Cat_QuickhealOutput
    CMC: CmcOutput
    ClamAV: ClamavOutput
    CrowdStrike: CrowdstrikeOutput
    Cylance: CylanceOutput
    Cynet: CynetOutput
    Cyren: CyrenOutput
    DrWeb: DrwebOutput
    ESET_NOD32: Eset_Nod32Output
    Elastic: ElasticOutput
    Emsisoft: EmsisoftOutput
    F_Secure: F_SecureOutput
    FireEye: FireeyeOutput
    Fortinet: FortinetOutput
    GData: GdataOutput
    Google: GoogleOutput
    Gridinsoft: GridinsoftOutput
    Ikarus: IkarusOutput
    Jiangmin: JiangminOutput
    K7AntiVirus: K7AntivirusOutput
    K7GW: K7GwOutput
    Kaspersky: KasperskyOutput
    Lionic: LionicOutput
    MAX: MaxOutput
    Malwarebytes: MalwarebytesOutput
    MaxSecure: MaxsecureOutput
    McAfee_GW_Edition: Mcafee_Gw_EditionOutput
    McAfee: McafeeOutput
    MicroWorld_eScan: Microworld_EscanOutput
    Microsoft: MicrosoftOutput
    NANO_Antivirus: Nano_AntivirusOutput
    Paloalto: PaloaltoOutput
    Panda: PandaOutput
    Rising: RisingOutput
    SUPERAntiSpyware: SuperantispywareOutput
    Sangfor: SangforOutput
    SentinelOne: SentineloneOutput
    Sophos: SophosOutput
    Symantec: SymantecOutput
    SymantecMobileInsight: SymantecmobileinsightOutput
    TACHYON: TachyonOutput
    Tencent: TencentOutput
    Trapmine: TrapmineOutput
    TrendMicro_HouseCall: Trendmicro_HousecallOutput
    TrendMicro: TrendmicroOutput
    Trustlook: TrustlookOutput
    VBA32: Vba32Output
    VIPRE: VipreOutput
    ViRobot: VirobotOutput
    VirIT: ViritOutput
    Webroot: WebrootOutput
    Xcitium: XcitiumOutput
    Yandex: YandexOutput
    Zillya: ZillyaOutput
    ZoneAlarm: ZonealarmOutput
    Zoner: ZonerOutput
    tehtris: TehtrisOutput


class StatsOutput(ActionOutput):
    confirmed_timeout: float = OutputField(example_values=[0], alias="confirmed-timeout")
    failure: float = OutputField(example_values=[0])
    harmless: float = OutputField(example_values=[0])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[0])
    timeout: float = OutputField(example_values=[0])
    type_unsupported: float = OutputField(example_values=[16], alias="type-unsupported")
    undetected: float = OutputField(example_values=[59])


class APILinks(ActionOutput):
    self: str = OutputField(
        cef_types=["url"],
        example_values=["https://www.virustotal.com/api/v3/files/e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"],
    )


class DataOutput(ActionOutput):
    attributes: AttributesOutput
    id: str = OutputField(
        cef_types=["virustotal scan id"],
        example_values=["MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw=="],
    )
    links: APILinks
    type: str = OutputField(example_values=["analysis"])


class FileInfoOutput(ActionOutput):
    md5: str = OutputField(cef_types=["md5"], example_values=["299999999992c49c91a0206ee7a8c00e659"])
    name: str = OutputField(example_values=["update_cr.py"])
    sha1: str = OutputField(cef_types=["sha1"], example_values=["9999999999142292710254cde97df84e46dfe33a"])
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=["e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"],
    )
    size: float = OutputField(example_values=[6285])


class MetaOutput(ActionOutput):
    file_info: FileInfoOutput


class DetonateFileOutput(ActionOutput):
    attributes: AttributesOutput
    data: DataOutput
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=["9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe"],
    )
    links: APILinks
    meta: MetaOutput
    type: str = OutputField(example_values=["file"])


@app.action(
    description="Upload a file to Virus Total and retrieve the analysis results",
    action_type="investigate",
    verbose="<b>detonate file</b> will send a file to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given file has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def detonate_file(params: DetonateFileParams, soar: SOARClient, asset: Asset) -> DetonateFileOutput:
    raise NotImplementedError()


class GetReportParams(Params):
    scan_id: str = Param(description="Scan ID", primary=True, cef_types=["virustotal scan id"])
    wait_time: float = Param(description="Number of seconds to wait", required=False)


class AdminuslabsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ADMINUSLabs"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Aicc_Monitorapp_Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["AICC (MONITORAPP)"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AlienvaultOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["AlienVault"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Antiy_AvlOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Antiy-AVL"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ArmisOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Armis"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ArtistsAgainst419Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Artists Against 419"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class AutoshunOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["AutoShun"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class AviraOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Avira"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class InfoOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["BADWARE.INFO"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BadwareOutput(ActionOutput):
    INFO: InfoOutput


class Baidu_InternationalOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Baidu-International"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BitdefenderOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["BitDefender"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BlocklistOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["BlockList"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class BluelivOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Blueliv"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CinsArmyOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CINS Army"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CleanMxOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CLEAN MX"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CmcThreatIntelligenceOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CMC Threat Intelligence"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CrdfOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CRDF"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CertegoOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Certego"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ComodoValkyrieVerdictOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Comodo Valkyrie Verdict"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class CyradarOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CyRadar"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CyanOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Cyan"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class CybercrimeOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["CyberCrime"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class CyrenOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Cyren"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Dns8Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["DNS8"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class WebOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Dr.Web"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class DrOutput(ActionOutput):
    Web: WebOutput


class EsetOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ESET"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EmergingthreatsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["EmergingThreats"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EmsisoftOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Emsisoft"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class EonscopeOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["EonScope"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class FeodoTrackerOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Feodo Tracker"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ForcepointThreatseekerOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Forcepoint ThreatSeeker"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class FortinetOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Fortinet"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class FraudscoreOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["FraudScore"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class G_DataOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["G-Data"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class GoogleSafebrowsingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Google Safebrowsing"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class GreensnowOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["GreenSnow"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class HopliteIndustriesOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Hoplite Industries"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class IpsumOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["IPsum"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class K7AntivirusOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["K7AntiVirus"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class KasperskyOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Kaspersky"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class LionicOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Lionic"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class LumuOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["Lumu"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class MalbeaconOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["MalBeacon"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalsiloOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["MalSilo"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwareDomainBlocklistOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Malware Domain Blocklist"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwaredomainlistOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["MalwareDomainList"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwarepatrolOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["MalwarePatrol"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwaredOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Malwared"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class NetcraftOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Netcraft"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class NotminingOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["NotMining"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class NucleonOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Nucleon"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class OpenphishOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["OpenPhish"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PrebytesOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["PREBYTES"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PhishlabsOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["PhishLabs"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class PhishingDatabaseOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Phishing Database"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class PhishtankOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Phishtank"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class QuickHealOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Quick Heal"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class QutteraOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Quttera"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class RisingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Rising"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class OrgOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["SCUMWARE.org"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ScumwareOutput(ActionOutput):
    org: OrgOutput


class SangforOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Sangfor"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SecurebrainOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["SecureBrain"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SnortIpSampleListOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Snort IP sample list"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SophosOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Sophos"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class Spam404Output(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Spam404"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SpamhausOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Spamhaus"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class StopbadwareOutput(ActionOutput):
    category: str = OutputField(example_values=["undetected"])
    engine_name: str = OutputField(example_values=["StopBadware"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["unrated"])


class StopforumspamOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["StopForumSpam"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class SucuriSitecheckOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Sucuri SiteCheck"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class TencentOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Tencent"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ThreathiveOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ThreatHive"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ThreatsourcingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Threatsourcing"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class TrustwaveOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Trustwave"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class UrlhausOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["URLhaus"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class VxVaultOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["VX Vault"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class VirusdieExternalSiteScanOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Virusdie External Site Scan"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class WebSecurityGuardOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Web Security Guard"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class YandexSafebrowsingOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["Yandex Safebrowsing"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ZerocertOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["ZeroCERT"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MeOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["desenmascara.me"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class DesenmascaraOutput(ActionOutput):
    me: MeOutput


class ComUrlCheckerOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["malwares.com URL checker"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class MalwaresOutput(ActionOutput):
    com_URL_checker: ComUrlCheckerOutput


class SecurolyticsOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["securolytics"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ZveloOutput(ActionOutput):
    category: str = OutputField(example_values=["harmless"])
    engine_name: str = OutputField(example_values=["zvelo"])
    method: str = OutputField(example_values=["blacklist"])
    result: str = OutputField(example_values=["clean"])


class ResultsOutput(ActionOutput):
    ADMINUSLabs: AdminuslabsOutput
    AICC__MONITORAPP_: Aicc_Monitorapp_Output
    AlienVault: AlienvaultOutput
    Antiy_AVL: Antiy_AvlOutput
    Armis: ArmisOutput
    Artists_Against_419: ArtistsAgainst419Output
    AutoShun: AutoshunOutput
    Avira: AviraOutput
    BADWARE: BadwareOutput
    Baidu_International: Baidu_InternationalOutput
    BitDefender: BitdefenderOutput
    BlockList: BlocklistOutput
    Blueliv: BluelivOutput
    CINS_Army: CinsArmyOutput
    CLEAN_MX: CleanMxOutput
    CMC_Threat_Intelligence: CmcThreatIntelligenceOutput
    CRDF: CrdfOutput
    Certego: CertegoOutput
    Comodo_Valkyrie_Verdict: ComodoValkyrieVerdictOutput
    CyRadar: CyradarOutput
    Cyan: CyanOutput
    CyberCrime: CybercrimeOutput
    Cyren: CyrenOutput
    DNS8: Dns8Output
    Dr: DrOutput
    ESET: EsetOutput
    EmergingThreats: EmergingthreatsOutput
    Emsisoft: EmsisoftOutput
    EonScope: EonscopeOutput
    Feodo_Tracker: FeodoTrackerOutput
    Forcepoint_ThreatSeeker: ForcepointThreatseekerOutput
    Fortinet: FortinetOutput
    FraudScore: FraudscoreOutput
    G_Data: G_DataOutput
    Google_Safebrowsing: GoogleSafebrowsingOutput
    GreenSnow: GreensnowOutput
    Hoplite_Industries: HopliteIndustriesOutput
    IPsum: IpsumOutput
    K7AntiVirus: K7AntivirusOutput
    Kaspersky: KasperskyOutput
    Lionic: LionicOutput
    Lumu: LumuOutput
    MalBeacon: MalbeaconOutput
    MalSilo: MalsiloOutput
    Malware_Domain_Blocklist: MalwareDomainBlocklistOutput
    MalwareDomainList: MalwaredomainlistOutput
    MalwarePatrol: MalwarepatrolOutput
    Malwared: MalwaredOutput
    Netcraft: NetcraftOutput
    NotMining: NotminingOutput
    Nucleon: NucleonOutput
    OpenPhish: OpenphishOutput
    PREBYTES: PrebytesOutput
    PhishLabs: PhishlabsOutput
    Phishing_Database: PhishingDatabaseOutput
    Phishtank: PhishtankOutput
    Quick_Heal: QuickHealOutput
    Quttera: QutteraOutput
    Rising: RisingOutput
    SCUMWARE: ScumwareOutput
    Sangfor: SangforOutput
    SecureBrain: SecurebrainOutput
    Snort_IP_sample_list: SnortIpSampleListOutput
    Sophos: SophosOutput
    Spam404: Spam404Output
    Spamhaus: SpamhausOutput
    StopBadware: StopbadwareOutput
    StopForumSpam: StopforumspamOutput
    Sucuri_SiteCheck: SucuriSitecheckOutput
    Tencent: TencentOutput
    ThreatHive: ThreathiveOutput
    Threatsourcing: ThreatsourcingOutput
    Trustwave: TrustwaveOutput
    URLhaus: UrlhausOutput
    VX_Vault: VxVaultOutput
    Virusdie_External_Site_Scan: VirusdieExternalSiteScanOutput
    Web_Security_Guard: WebSecurityGuardOutput
    Yandex_Safebrowsing: YandexSafebrowsingOutput
    ZeroCERT: ZerocertOutput
    desenmascara: DesenmascaraOutput
    malwares: MalwaresOutput
    securolytics: SecurolyticsOutput
    zvelo: ZveloOutput


class StatsOutput(ActionOutput):
    harmless: float = OutputField(example_values=[76])
    malicious: float = OutputField(example_values=[0])
    suspicious: float = OutputField(example_values=[0])
    timeout: float = OutputField(example_values=[0])
    undetected: float = OutputField(example_values=[7])


class AttributesOutput(ActionOutput):
    date: float = OutputField(example_values=[1613467266])
    results: ResultsOutput
    stats: StatsOutput
    status: str = OutputField(example_values=["completed"])


class APILinks(ActionOutput):
    item: str = OutputField(
        example_values=["https://www.virustotal.com/api/v3/urls/f351f690f46ea50132cc1da00d1f1e2a537bb40f8db5dbf777221981d8d49354"]
    )
    self: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://www.virustotal.com/api/v3/analyses/u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266"
        ],
    )


class DataOutput(ActionOutput):
    attributes: AttributesOutput
    id: str = OutputField(example_values=["u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266"])
    links: APILinks
    type: str = OutputField(example_values=["analysis"])


class FileInfoOutput(ActionOutput):
    sha256: str = OutputField(example_values=["9999999999149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])


class UrlInfoOutput(ActionOutput):
    id: str = OutputField(
        cef_types=["sha256"],
        example_values=["19999999999e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488"],
    )
    url: str = OutputField(example_values=["http://shinedezign.tk/"])


class MetaOutput(ActionOutput):
    file_info: FileInfoOutput
    url_info: UrlInfoOutput


class GetReportOutput(ActionOutput):
    data: DataOutput
    meta: MetaOutput


@app.action(
    description="Get the results using the scan id from a detonate file or detonate url action",
    action_type="investigate",
    verbose="For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.",
)
def get_report(params: GetReportParams, soar: SOARClient, asset: Asset) -> GetReportOutput:
    raise NotImplementedError()


class GetCachedEntriesOutput(ActionOutput):
    date_added: str
    date_expires: str
    key: str
    seconds_left: float


@app.action(description="Get listing of cached entries", action_type="investigate")
def get_cached_entries(params: Params, soar: SOARClient, asset: Asset) -> GetCachedEntriesOutput:
    raise NotImplementedError()


class ClearCacheOutput(ActionOutput):
    status: str = OutputField(example_values=["success"])


@app.action(description="Clear all cached entries", action_type="generic", read_only=False)
def clear_cache(params: Params, soar: SOARClient, asset: Asset) -> ClearCacheOutput:
    raise NotImplementedError()


class GetQuotasParams(Params):
    user_id: str = Param(description="The username or API key to use to fetch quotas")


class GroupOutput(ActionOutput):
    allowed: float = OutputField(example_values=[0])
    inherited_from: str = OutputField(example_values=["testuser"])
    used: float = OutputField(example_values=[0])


class UserOutput(ActionOutput):
    allowed: float = OutputField(example_values=[0])
    used: float = OutputField(example_values=[0])


class ApiRequestsDailyOutput(ActionOutput):
    group: GroupOutput
    user: UserOutput


class ApiRequestsHourlyOutput(ActionOutput):
    group: GroupOutput
    user: UserOutput


class ApiRequestsMonthlyOutput(ActionOutput):
    group: GroupOutput
    user: UserOutput


class CollectionsCreationMonthlyOutput(ActionOutput):
    user: UserOutput


class IntelligenceDownloadsMonthlyOutput(ActionOutput):
    user: UserOutput


class IntelligenceGraphsPrivateOutput(ActionOutput):
    user: UserOutput


class IntelligenceHuntingRulesOutput(ActionOutput):
    user: UserOutput


class IntelligenceRetrohuntJobsMonthlyOutput(ActionOutput):
    user: UserOutput


class IntelligenceSearchesMonthlyOutput(ActionOutput):
    user: UserOutput


class IntelligenceVtdiffCreationMonthlyOutput(ActionOutput):
    user: UserOutput


class MonitorStorageBytesOutput(ActionOutput):
    user: UserOutput


class MonitorStorageFilesOutput(ActionOutput):
    user: UserOutput


class MonitorUploadedBytesOutput(ActionOutput):
    user: UserOutput


class MonitorUploadedFilesOutput(ActionOutput):
    user: UserOutput


class PrivateScansMonthlyOutput(ActionOutput):
    user: UserOutput


class PrivateScansPerMinuteOutput(ActionOutput):
    user: UserOutput


class GetQuotasOutput(ActionOutput):
    api_requests_daily: ApiRequestsDailyOutput
    api_requests_hourly: ApiRequestsHourlyOutput
    api_requests_monthly: ApiRequestsMonthlyOutput
    collections_creation_monthly: CollectionsCreationMonthlyOutput
    intelligence_downloads_monthly: IntelligenceDownloadsMonthlyOutput
    intelligence_graphs_private: IntelligenceGraphsPrivateOutput
    intelligence_hunting_rules: IntelligenceHuntingRulesOutput
    intelligence_retrohunt_jobs_monthly: IntelligenceRetrohuntJobsMonthlyOutput
    intelligence_searches_monthly: IntelligenceSearchesMonthlyOutput
    intelligence_vtdiff_creation_monthly: IntelligenceVtdiffCreationMonthlyOutput
    monitor_storage_bytes: MonitorStorageBytesOutput
    monitor_storage_files: MonitorStorageFilesOutput
    monitor_uploaded_bytes: MonitorUploadedBytesOutput
    monitor_uploaded_files: MonitorUploadedFilesOutput
    private_scans_monthly: PrivateScansMonthlyOutput
    private_scans_per_minute: PrivateScansPerMinuteOutput


@app.action(
    description="Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details",
    action_type="investigate",
)
def get_quotas(params: GetQuotasParams, soar: SOARClient, asset: Asset) -> GetQuotasOutput:
    raise NotImplementedError()


if __name__ == "__main__":
    app.cli()
