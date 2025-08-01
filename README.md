# VirusTotal v3

Publisher: Splunk \
Connector Version: 1.8.3 \
Product Vendor: VirusTotal \
Product Name: VirusTotal v3 \
Minimum Product Version: 6.2.1

This app integrates with the VirusTotal cloud to implement investigative and reputation actions using v3 APIs

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the VirusTotal server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

## Cache Flow

If caching is enabled and whenever you run any reputation action then the output of the action will
be cached in the state file of the asset for which it is run. This cache will have an expiration
time and maximum length, after the expiration time you have set in asset configuration if you run
the get cached entries it will clear the cache.

### Configuration variables

This table lists the configuration variables required to operate VirusTotal v3. These variables are specified when configuring a VirusTotal v3 asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** | required | password | VirusTotal API key |
**poll_interval** | optional | numeric | Number of minutes to poll for a detonation result (Default: 5) |
**waiting_time** | optional | numeric | Number of seconds to wait before polling for a detonation result (Default: 0) |
**rate_limit** | optional | boolean | Limit number of requests to 4 per minute |
**timeout** | optional | numeric | Request Timeout (Default: 30 seconds) |
**cache_reputation_checks** | optional | boolean | Cache virustotal reputation checks |
**cache_expiration_interval** | optional | numeric | Number of seconds until cached reputation checks expire. Any other value than positive integer will disable caching (Default: 3600 seconds) |
**cache_size** | optional | numeric | Maximum number of entries in cache. Values of zero or less will not limit size and decimal value will be converted to floor value (Default: 1000) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[domain reputation](#action-domain-reputation) - Queries VirusTotal for domain info \
[file reputation](#action-file-reputation) - Queries VirusTotal for file reputation info \
[get file](#action-get-file) - Downloads a file from VirusTotal and adds it to the vault \
[ip reputation](#action-ip-reputation) - Queries VirusTotal for IP info \
[url reputation](#action-url-reputation) - Queries VirusTotal for URL info (run this action after running detonate url) \
[detonate url](#action-detonate-url) - Load a URL to Virus Total and retrieve analysis results \
[detonate file](#action-detonate-file) - Upload a file to Virus Total and retrieve the analysis results \
[get report](#action-get-report) - Get the results using the scan id from a detonate file or detonate url action \
[get cached entries](#action-get-cached-entries) - Get listing of cached entries \
[clear cache](#action-clear-cache) - Clear all cached entries \
[get quotas](#action-get-quotas) - Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'domain reputation'

Queries VirusTotal for domain info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to query | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` | test.com |
action_result.data.\*.attributes.categories.BitDefender | string | | searchengines |
action_result.data.\*.attributes.categories.Comodo Valkyrie Verdict | string | | mobile communications |
action_result.data.\*.attributes.categories.Dr.Web | string | | social networks |
action_result.data.\*.attributes.categories.Forcepoint ThreatSeeker | string | | search engines and portals |
action_result.data.\*.attributes.categories.Sophos | string | | social networks |
action_result.data.\*.attributes.categories.Xcitium Verdict Cloud | string | | mobile communications |
action_result.data.\*.attributes.categories.alphaMountain.ai | string | | Social Networking |
action_result.data.\*.attributes.categories.sophos | string | | search engines |
action_result.data.\*.attributes.creation_date | numeric | | 874296000 |
action_result.data.\*.attributes.jarm | string | | 27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d |
action_result.data.\*.attributes.last_analysis_date | numeric | | 1677738648 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | harmless |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CRDF |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | clean |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | Symantec |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | 90 |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | 8 |
action_result.data.\*.attributes.last_dns_records.\*.expire | numeric | | 1800 |
action_result.data.\*.attributes.last_dns_records.\*.flag | numeric | | 0 |
action_result.data.\*.attributes.last_dns_records.\*.minimum | numeric | | 60 |
action_result.data.\*.attributes.last_dns_records.\*.priority | numeric | | 40 |
action_result.data.\*.attributes.last_dns_records.\*.refresh | numeric | | 900 |
action_result.data.\*.attributes.last_dns_records.\*.retry | numeric | | 900 |
action_result.data.\*.attributes.last_dns_records.\*.rname | string | | dns-admin.test.com |
action_result.data.\*.attributes.last_dns_records.\*.serial | numeric | | 357917103 |
action_result.data.\*.attributes.last_dns_records.\*.tag | string | | issue |
action_result.data.\*.attributes.last_dns_records.\*.ttl | numeric | | 78 |
action_result.data.\*.attributes.last_dns_records.\*.type | string | | MX |
action_result.data.\*.attributes.last_dns_records.\*.value | string | `ip` | alt3.aspmx.l.test.com |
action_result.data.\*.attributes.last_dns_records_date | numeric | | 1613638555 |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature | string | | 811fa6e0af210a512fa773cf16fd62ecae6fdacab57fb71626791b9ad5bfb19841435e7480dba67b1fd17828204f05905379bccc98a7f39a037a5b4eb43f3bb54c51df02137b13abffc343b500319819854920af065afb70a3857657909b0d006de9b7aa2197fe94c2ccde7df14760dd8c5f87d5f89c3b1b835c81f06b727d5ea21fc04c0126ef1377cceb935ccedc969b6b503e5e3c783f0fb13f7dd465d67b807f9d268082449813eb0700e7bd472b238f8c551c07b3e130b88b7fb96799e6d9c1ac8b632603840eeb429e271856a94cd62f1d1bdfeda4f02ae0df7b1d0b80aceab4b73d137f4b4bec851555213fc540dc74defb81761304e3339062d65a60 |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature_algorithm | string | | sha256RSA |
action_result.data.\*.attributes.last_https_certificate.extensions.1.3.6.1.4.1.11129.2.4.2 | string | `sha256` | 0481f100ef0076007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e |
action_result.data.\*.attributes.last_https_certificate.extensions.CA | boolean | | True |
action_result.data.\*.attributes.last_https_certificate.extensions.authority_key_identifier.keyid | string | `sha1` | 98d1f86e10ebcf9bec609f18901ba0eb7d09fd2b |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.CA Issuers | string | `url` | http://pki.goog/gsr2/GTS1O1.crt |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.OCSP | string | `url` | http://ocsp.pki.goog/gts1o1core |
action_result.data.\*.attributes.last_https_certificate.extensions.certificate_policies | string | | 1.3.6.1.4.1.11129.2.5.3 |
action_result.data.\*.attributes.last_https_certificate.extensions.crl_distribution_points | string | `url` | http://crl.pki.goog/GTS1O1core.crl |
action_result.data.\*.attributes.last_https_certificate.extensions.extended_key_usage | string | | serverAuth |
action_result.data.\*.attributes.last_https_certificate.extensions.key_usage | string | | ff |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_alternative_name | string | | yt.be |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_key_identifier | string | `sha1` | 67bf0513cc1c9c4765c43f3fedd687cf88bcd93d |
action_result.data.\*.attributes.last_https_certificate.issuer.C | string | | US |
action_result.data.\*.attributes.last_https_certificate.issuer.CN | string | | GTS CA 1O1 |
action_result.data.\*.attributes.last_https_certificate.issuer.L | string | | Salford |
action_result.data.\*.attributes.last_https_certificate.issuer.O | string | | Test Trust Services |
action_result.data.\*.attributes.last_https_certificate.issuer.OU | string | | www.test.com |
action_result.data.\*.attributes.last_https_certificate.issuer.ST | string | | Greater Manchester |
action_result.data.\*.attributes.last_https_certificate.public_key.algorithm | string | | EC |
action_result.data.\*.attributes.last_https_certificate.public_key.ec.oid | string | | secp256r1 |
action_result.data.\*.attributes.last_https_certificate.public_key.ec.pub | string | | 0453d3053c10d8cc8d06a01c02171e8c2d91b355cc188112943a217edc2fe60e3592f329404573e124c077917dcf319f14a6a2c3e433ee695d60a7e9ba3883aa5b |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.exponent | string | | 010001 |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.key_size | numeric | | 2048 |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.modulus | string | | 9999999999a6ad2efd8570b904c9bffa81153979c1a9b1415ba44f2057004b18bc2eb767e6ac209999a6a83d51de01433d9d2606b13646a11ca968dfaa3752d2dae79ec97d5dccae86e51c0cbf5dce4584217ca9b7142c568f1a6a0f54cbd4055d0b71104d8e3ed79e958829324e6c10c90c4e11b57d430af2ba89d5e333c9538661b5a61fdf7164970dbfd9817cf5b585d4f2180a526426ac64087a81e13ae4668141abcff65e9038cde7ca5039285beb99c6fbbb75e6c72df66c0551e38123e0984f634c7b442a932bf72fec6d4e5908e773943a6fd16310df8c9ac79f934d0264bb900246c8a5832b489c475dd0d1eb4670e5b7691f25facdd687531 |
action_result.data.\*.attributes.last_https_certificate.serial_number | string | `md5` | c4ea98ea7e5e1f430200000000870182 |
action_result.data.\*.attributes.last_https_certificate.signature_algorithm | string | | sha256RSA |
action_result.data.\*.attributes.last_https_certificate.size | numeric | | 2441 |
action_result.data.\*.attributes.last_https_certificate.subject.C | string | | US |
action_result.data.\*.attributes.last_https_certificate.subject.CN | string | | \*.test.com |
action_result.data.\*.attributes.last_https_certificate.subject.L | string | | Mountain View |
action_result.data.\*.attributes.last_https_certificate.subject.O | string | | Test LLC |
action_result.data.\*.attributes.last_https_certificate.subject.ST | string | | California |
action_result.data.\*.attributes.last_https_certificate.thumbprint | string | `sha1` | c25b1dc8be5f679087ecd28fb5eae7b3985cf604 |
action_result.data.\*.attributes.last_https_certificate.thumbprint_sha256 | string | `sha256` | a29f9d0d85bd02b3150267ac5a820e4aadc9becc7b5884530a549e6d98dac4a3 |
action_result.data.\*.attributes.last_https_certificate.validity.not_after | string | | 2021-04-13 07:57:08 |
action_result.data.\*.attributes.last_https_certificate.validity.not_before | string | | 2021-01-19 07:57:09 |
action_result.data.\*.attributes.last_https_certificate.version | string | | V3 |
action_result.data.\*.attributes.last_https_certificate_date | numeric | | 1613638555 |
action_result.data.\*.attributes.last_modification_date | numeric | | 1613640948 |
action_result.data.\*.attributes.last_update_date | numeric | | 1568043544 |
action_result.data.\*.attributes.popularity_ranks.Alexa.rank | numeric | | 1 |
action_result.data.\*.attributes.popularity_ranks.Alexa.timestamp | numeric | | 1613576161 |
action_result.data.\*.attributes.popularity_ranks.Cisco Umbrella.rank | numeric | | 1 |
action_result.data.\*.attributes.popularity_ranks.Cisco Umbrella.timestamp | numeric | | 1613489762 |
action_result.data.\*.attributes.popularity_ranks.Majestic.rank | numeric | | 2 |
action_result.data.\*.attributes.popularity_ranks.Majestic.timestamp | numeric | | 1613576163 |
action_result.data.\*.attributes.popularity_ranks.Quantcast.rank | numeric | | 1 |
action_result.data.\*.attributes.popularity_ranks.Quantcast.timestamp | numeric | | 1585755370 |
action_result.data.\*.attributes.popularity_ranks.Statvoo.rank | numeric | | 1 |
action_result.data.\*.attributes.popularity_ranks.Statvoo.timestamp | numeric | | 1613576162 |
action_result.data.\*.attributes.registrar | string | | MarkMonitor Inc. |
action_result.data.\*.attributes.reputation | numeric | | 256 |
action_result.data.\*.attributes.tld | string | | com |
action_result.data.\*.attributes.total_votes.harmless | numeric | | 104 |
action_result.data.\*.attributes.total_votes.malicious | numeric | | 26 |
action_result.data.\*.attributes.whois | string | | test data Creation Date: 1997-09-15T04:00:00Z DNSSEC: unsigned Domain Name: TEST.COM Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited |
action_result.data.\*.attributes.whois_date | numeric | | 1612787278 |
action_result.data.\*.id | string | `domain` | test.com |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.type | string | | domain |
action_result.summary.harmless | numeric | | 90 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.source | string | | new from virustotal |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 8 |
action_result.message | string | | Harmless: 90, Malicious: 0, Suspicious: 0, Undetected: 8 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'file reputation'

Queries VirusTotal for file reputation info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | File hash to query | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | 999999999999c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.attributes.authentihash | string | | 999999990b465f7bd1e7568640397f01fc4f8819ce6f0c1415690ecee646464cec |
action_result.data.\*.attributes.creation_date | numeric | | 1410950077 |
action_result.data.\*.attributes.detectiteasy.filetype | string | | PE32 |
action_result.data.\*.attributes.detectiteasy.values.\*.info | string | | EXE32 |
action_result.data.\*.attributes.detectiteasy.values.\*.name | string | | EP:Microsoft Visual C/C++ |
action_result.data.\*.attributes.detectiteasy.values.\*.type | string | | Compiler |
action_result.data.\*.attributes.detectiteasy.values.\*.version | string | | 2008-2010 |
action_result.data.\*.attributes.first_submission_date | numeric | | 1612961082 |
action_result.data.\*.attributes.last_analysis_date | numeric | | 1613635130 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | undetected |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.\*.engine_update | string | | 20210218 |
action_result.data.\*.attributes.last_analysis_results.\*.engine_version | string | | 2.10.2019.1 |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | Symantec |
action_result.data.\*.attributes.last_analysis_stats.confirmed-timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.failure | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.type-unsupported | numeric | | 16 |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | 59 |
action_result.data.\*.attributes.last_modification_date | numeric | | 1613635210 |
action_result.data.\*.attributes.last_submission_date | numeric | | 1613635130 |
action_result.data.\*.attributes.magic | string | | a python2.7\\015script text executable |
action_result.data.\*.attributes.md5 | string | `md5` | 2e65153f2c49c91a0206ee7a8c00e659 |
action_result.data.\*.attributes.meaningful_name | string | | update_cr.py |
action_result.data.\*.attributes.names | string | | update_cr.py |
action_result.data.\*.attributes.pdf_info.acroform | numeric | | |
action_result.data.\*.attributes.pdf_info.autoaction | numeric | | |
action_result.data.\*.attributes.pdf_info.embedded_file | numeric | | |
action_result.data.\*.attributes.pdf_info.encrypted | numeric | | |
action_result.data.\*.attributes.pdf_info.flash | numeric | | |
action_result.data.\*.attributes.pdf_info.header | string | | %PDF-1.5 |
action_result.data.\*.attributes.pdf_info.javascript | numeric | | |
action_result.data.\*.attributes.pdf_info.jbig2_compression | numeric | | |
action_result.data.\*.attributes.pdf_info.js | numeric | | |
action_result.data.\*.attributes.pdf_info.num_endobj | numeric | | 29 |
action_result.data.\*.attributes.pdf_info.num_endstream | numeric | | 28 |
action_result.data.\*.attributes.pdf_info.num_launch_actions | numeric | | |
action_result.data.\*.attributes.pdf_info.num_obj | numeric | | 29 |
action_result.data.\*.attributes.pdf_info.num_object_streams | numeric | | 1 |
action_result.data.\*.attributes.pdf_info.num_pages | numeric | | |
action_result.data.\*.attributes.pdf_info.num_stream | numeric | | 28 |
action_result.data.\*.attributes.pdf_info.openaction | numeric | | |
action_result.data.\*.attributes.pdf_info.startxref | numeric | | 1 |
action_result.data.\*.attributes.pdf_info.suspicious_colors | numeric | | |
action_result.data.\*.attributes.pdf_info.trailer | numeric | | |
action_result.data.\*.attributes.pdf_info.xfa | numeric | | |
action_result.data.\*.attributes.pdf_info.xref | numeric | | |
action_result.data.\*.attributes.pe_info.entry_point | numeric | | 14768 |
action_result.data.\*.attributes.pe_info.imphash | string | | 999984447a5c5ca9b4a55946317137951 |
action_result.data.\*.attributes.pe_info.import_list.\*.library_name | string | | COMDLG32.dll |
action_result.data.\*.attributes.pe_info.machine_type | numeric | | 332 |
action_result.data.\*.attributes.pe_info.resource_details.\*.chi2 | numeric | | 8137.34814453125 |
action_result.data.\*.attributes.pe_info.resource_details.\*.entropy | numeric | | 5.789552211761475 |
action_result.data.\*.attributes.pe_info.resource_details.\*.filetype | string | | Data |
action_result.data.\*.attributes.pe_info.resource_details.\*.lang | string | | ENGLISH US |
action_result.data.\*.attributes.pe_info.resource_details.\*.sha256 | string | | 999999999981e8d88978836b23ee932ade6652ba798989bf20697afffd6113e |
action_result.data.\*.attributes.pe_info.resource_details.\*.type | string | | RT_BITMAP |
action_result.data.\*.attributes.pe_info.resource_langs.ENGLISH US | numeric | | 6 |
action_result.data.\*.attributes.pe_info.resource_langs.RUSSIAN | numeric | | 1 |
action_result.data.\*.attributes.pe_info.resource_types.RT_BITMAP | numeric | | 2 |
action_result.data.\*.attributes.pe_info.resource_types.RT_DIALOG | numeric | | 2 |
action_result.data.\*.attributes.pe_info.resource_types.RT_MANIFEST | numeric | | 1 |
action_result.data.\*.attributes.pe_info.resource_types.RT_MENU | numeric | | 1 |
action_result.data.\*.attributes.pe_info.resource_types.RT_VERSION | numeric | | 1 |
action_result.data.\*.attributes.pe_info.rich_pe_header_hash | string | | fa4dbca9180170710b3c245464efa483 |
action_result.data.\*.attributes.pe_info.sections.\*.chi2 | numeric | | 292981.44 |
action_result.data.\*.attributes.pe_info.sections.\*.entropy | numeric | | 6.75 |
action_result.data.\*.attributes.pe_info.sections.\*.flags | string | | rx |
action_result.data.\*.attributes.pe_info.sections.\*.md5 | string | | 99999998c3e0636712e10326c07d56b645 |
action_result.data.\*.attributes.pe_info.sections.\*.name | string | | .text |
action_result.data.\*.attributes.pe_info.sections.\*.raw_size | numeric | | 54784 |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_address | numeric | | 4096 |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_size | numeric | | 54434 |
action_result.data.\*.attributes.pe_info.timestamp | numeric | | 1410950077 |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.count | numeric | | 30 |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.value | string | | trojan |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.count | numeric | | 13 |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.value | string | | zbot |
action_result.data.\*.attributes.popular_threat_classification.suggested_threat_label | string | | trojan.zbot/foreign |
action_result.data.\*.attributes.reputation | numeric | | 0 |
action_result.data.\*.attributes.sandbox_verdicts.Tencent HABO.\* | string | | xyz |
action_result.data.\*.attributes.sandbox_verdicts.Tencent HABO.category | string | | malicious |
action_result.data.\*.attributes.sandbox_verdicts.Tencent HABO.sandbox_name | string | | Tencent HABO |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.category | string | | harmless |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.confidence | numeric | | 1 |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.sandbox_name | string | | Zenbox |
action_result.data.\*.attributes.sha1 | string | `sha1` | 9999969a19142292710254cde97df84e46dfe33a |
action_result.data.\*.attributes.sha256 | string | `sha256` | 9999999ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.attributes.signature_info.\* | string | | xyz |
action_result.data.\*.attributes.signature_info.copyright | string | | Copyright 2003-2013 |
action_result.data.\*.attributes.signature_info.description | string | | WinMerge Shell Integration |
action_result.data.\*.attributes.signature_info.file version | string | | 1.0.1.6 |
action_result.data.\*.attributes.signature_info.internal name | string | | ShellExtension |
action_result.data.\*.attributes.signature_info.original name | string | | ShellExtension |
action_result.data.\*.attributes.signature_info.product | string | | ShellExtension |
action_result.data.\*.attributes.size | numeric | | 6285 |
action_result.data.\*.attributes.ssdeep | string | | 192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygiINVALIDu7ThPBLkv:pq7Mgg0/NdMu/1BLkv |
action_result.data.\*.attributes.tags | string | | python |
action_result.data.\*.attributes.times_submitted | numeric | | 13 |
action_result.data.\*.attributes.tlsh | string | | 9999999905AC5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC |
action_result.data.\*.attributes.total_votes.harmless | numeric | | 0 |
action_result.data.\*.attributes.total_votes.malicious | numeric | | 0 |
action_result.data.\*.attributes.trid.\*.file_type | string | | Unix-like shebang (var.1) (gen) |
action_result.data.\*.attributes.trid.\*.probability | numeric | | 100 |
action_result.data.\*.attributes.type_description | string | | Python |
action_result.data.\*.attributes.type_extension | string | | py |
action_result.data.\*.attributes.type_tag | string | | python |
action_result.data.\*.attributes.unique_sources | numeric | | 1 |
action_result.data.\*.attributes.vhash | string | | 999996657d755510804011z9005b9z25z12z3afz |
action_result.data.\*.id | string | `sha256` | 9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/files/e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.type | string | | file |
action_result.summary.harmless | numeric | | 0 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.source | string | | new from virustotal |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 59 |
action_result.message | string | | Harmless: 0, Malicious: 0, Suspicious: 0, Undetected: 59 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get file'

Downloads a file from VirusTotal and adds it to the vault

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash of file to get | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'ip reputation'

Queries VirusTotal for IP info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to query | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` `ipv6` | 2.3.4.5 |
action_result.data.\*.attributes.as_owner | string | | Orange |
action_result.data.\*.attributes.asn | numeric | | 3215 |
action_result.data.\*.attributes.continent | string | | EU |
action_result.data.\*.attributes.country | string | | FR |
action_result.data.\*.attributes.crowdsourced_context.\*.detail | string | | A domain seen in a CnC panel URL for the Oski malware resolved to this IP address |
action_result.data.\*.attributes.crowdsourced_context.\*.severity | string | | high |
action_result.data.\*.attributes.crowdsourced_context.\*.source | string | | benkow.cc |
action_result.data.\*.attributes.crowdsourced_context.\*.timestamp | numeric | | 1622592000 |
action_result.data.\*.attributes.crowdsourced_context.\*.title | string | | CnC Panel |
action_result.data.\*.attributes.jarm | string | | 29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae |
action_result.data.\*.attributes.last_analysis_date | numeric | | 1679467461 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | harmless |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CRDF |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | clean |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | Symantec |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | 86 |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | 11 |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature | string | | 9999999991eed2a66b7aef3c70912cd032acbd2c8791021a3c8cb90b38c579d5fa02d04e4e897b1762981b455d77cea92c56bcf902451a76148582a1e80acc1aeb2a0d72f7e8db8739f874e83a48553311eb3cfe48a0d065a309cedf35930ae3e2cb0d4dca8dba64dc7b5f707debac4f28ce313db8623e235790002b37a8dbc63c99276335c4a59faf1957d5384fc318c56b159e51213c21699e328821f64efc433d74372962d6d160f92b5f1dbbc4e8e11c74ce673e8c52f6270c40c1192cf7bf2bbf44660818b8999085388ac8949332f178b294d409334e8d70ca051a5a7ed53df82e58a46ee2c07afa08f0e0f9ea87311f1a8e79ad3406292e811a5c6 |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature_algorithm | string | | sha256RSA |
action_result.data.\*.attributes.last_https_certificate.extensions.1.3.6.1.4.1.11129.2.4.2 | string | | 999999100ef007600eec095ee8d72640f92e3c3b91bc712a3696a097b4b6a1a14 |
action_result.data.\*.attributes.last_https_certificate.extensions.CA | boolean | | True |
action_result.data.\*.attributes.last_https_certificate.extensions.authority_key_identifier.keyid | string | | 999997faf85cdee95cd3d9cd0e24614f371351d27 |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.CA Issuers | string | | http://pki.goog/repo/certs/gts1c3.der |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.OCSP | string | | http://ocsp.pki.goog/gts1c3 |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_key_identifier | string | | 9999921f3772284cf53c30f681f14bf6ed035cd9 |
action_result.data.\*.attributes.last_https_certificate.issuer.\* | string | | xyz |
action_result.data.\*.attributes.last_https_certificate.issuer.C | string | | US |
action_result.data.\*.attributes.last_https_certificate.issuer.CN | string | | GTS CA 1C3 |
action_result.data.\*.attributes.last_https_certificate.issuer.O | string | | Google Trust Services LLC |
action_result.data.\*.attributes.last_https_certificate.public_key.algorithm | string | | RSA |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.exponent | string | | 010001 |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.key_size | numeric | | 2048 |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.modulus | string | | 999999999f74bea72e3cb68a2a6bb74521f2ee951338a5d9f6a738f98996e2d72295009f544112aa918e99b93ab48f073322711b992887a46211dc853c48e2f22372419c8841221f3dad453289c2331d3b4c881c67660ecc5093bf601130a7aef9f54419ee8e64754c3b07125893af7dabf0bb0f7232d0226605620e12a4416fb22d5c9182394941b218009f6fe2d28d170a1042a0aa726eb9b052a84a57597a4b9a556be00c004ba024bd310d9e4faf17482b137f81b35f470ead7d7d9e418a6653799e9d04f9fd1d4b588809c0e2ac0680f406ba8f4358a143e3cacc7fe792ab9655cc73729dbcd3d7362a7ffe6f903942dc3d588c97917930a9b28b8561c9219b |
action_result.data.\*.attributes.last_https_certificate.serial_number | string | | 999999999f93320b7b0a00000000f2c8e9 |
action_result.data.\*.attributes.last_https_certificate.signature_algorithm | string | | sha256RSA |
action_result.data.\*.attributes.last_https_certificate.size | numeric | | 1509 |
action_result.data.\*.attributes.last_https_certificate.subject.CN | string | | dns.test |
action_result.data.\*.attributes.last_https_certificate.thumbprint | string | | 999999993948b043f8f258cceebe9eb7a8dd7d06de |
action_result.data.\*.attributes.last_https_certificate.thumbprint_sha256 | string | | 999999e0344c78df40dfcfc2ecd6f83d01b4bcf1def8c548c87691211d904f05 |
action_result.data.\*.attributes.last_https_certificate.validity.not_after | string | | 2021-10-04 03:52:55 |
action_result.data.\*.attributes.last_https_certificate.validity.not_before | string | | 2021-07-12 03:52:56 |
action_result.data.\*.attributes.last_https_certificate.version | string | | V3 |
action_result.data.\*.attributes.last_https_certificate_date | numeric | | 1628548284 |
action_result.data.\*.attributes.last_modification_date | numeric | | 1612735030 |
action_result.data.\*.attributes.network | string | | 2.0.0.0/12 |
action_result.data.\*.attributes.regional_internet_registry | string | | RIPE NCC |
action_result.data.\*.attributes.reputation | numeric | | 0 |
action_result.data.\*.attributes.total_votes.harmless | numeric | | 0 |
action_result.data.\*.attributes.total_votes.malicious | numeric | | 0 |
action_result.data.\*.attributes.whois | string | | Test data NetRange: 2.0.0.0 - 2.255.255.255 CIDR: 2.0.0.0/8 NetName: 2-RIPE NetHandle: NET-2-0-0-0-1 Parent: () NetType: Allocated to RIPE NCC OriginAS: Organization: RIPE Network Coordination Centre (RIPE) RegDate: 2009-09-29 Updated: 2009-09-30 Comment: These addresses have been further assigned to users in Comment: the RIPE NCC region. Contact information can be found in Comment: the RIPE database at http://www.ripe.net/whois Ref: https://rdap.arin.net/registry/ip/2.0.0.0 ResourceLink: https://apps.db.ripe.net/search/query.html ResourceLink: whois.ripe.net OrgName: RIPE Network Coordination Centre OrgId: RIPE Address: P.O. Box 10096 City: Amsterdam StateProv: PostalCode: 1001EB Country: NL RegDate: Updated: 2013-07-29 Ref: https://rdap.arin.net/registry/entity/RIPE ReferralServer: whois://whois.ripe.net ResourceLink: https://apps.db.ripe.net/search/query.html OrgAbuseHandle: ABUSE3850-ARIN OrgAbuseName: Abuse Contact OrgAbusePhone: +31205354444 OrgAbuseEmail: abuse@ripe.net OrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE3850-ARIN OrgTechHandle: RNO29-ARIN OrgTechName: RIPE NCC Operations OrgTechPhone: +31 20 535 4444 OrgTechEmail: hostmaster@ripe.net OrgTechRef: https://rdap.arin.net/registry/entity/RNO29-ARIN inetnum: 2.3.0.0 - 2.3.7.255 netname: IP2000-ADSL-BAS descr: POP CLE country: FR admin-c: WITR1-RIPE tech-c: WITR1-RIPE status: ASSIGNED PA remarks: for hacking, spamming or security problems send mail to remarks: abuse@orange.fr mnt-by: FT-BRX created: 2017-07-27T08:58:11Z last-modified: 2017-07-27T08:58:11Z source: RIPE role: Wanadoo France Technical Role address: FRANCE TELECOM/SCR address: 48 rue Camille Desmoulins address: 92791 ISSY LES MOULINEAUX CEDEX 9 address: FR phone: +33 1 58 88 50 00 abuse-mailbox: abuse@orange.fr admin-c: BRX1-RIPE tech-c: BRX1-RIPE nic-hdl: WITR1-RIPE mnt-by: FT-BRX created: 2001-12-04T17:57:08Z last-modified: 2013-07-16T14:09:50Z source: RIPE # Filtered route: 2.3.0.0/16 descr: France Telecom Orange origin: AS3215 mnt-by: RAIN-TRANSPAC mnt-by: FT-BRX created: 2012-11-22T09:32:05Z |
action_result.data.\*.attributes.whois_date | numeric | | 1612735030 |
action_result.data.\*.id | string | `ip` | 2.3.4.5 |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/ip_addresses/2.3.4.5 |
action_result.data.\*.type | string | | ip_address |
action_result.summary.harmless | numeric | | 86 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.source | string | | new from virustotal |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 11 |
action_result.message | string | | Harmless: 86, Malicious: 0, Suspicious: 0, Undetected: 11 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'url reputation'

Queries VirusTotal for URL info (run this action after running detonate url)

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` `domain` | http://www.test123.com |
action_result.data.\*.attributes.categories.\* | string | | searchengines |
action_result.data.\*.attributes.categories.BitDefender | string | | computersandsoftware |
action_result.data.\*.attributes.categories.Comodo Valkyrie Verdict | string | | media sharing |
action_result.data.\*.attributes.categories.Dr.Web | string | | e-mail |
action_result.data.\*.attributes.categories.Forcepoint ThreatSeeker | string | | information technology |
action_result.data.\*.attributes.categories.Sophos | string | | information technology |
action_result.data.\*.attributes.categories.Xcitium Verdict Cloud | string | | media sharing |
action_result.data.\*.attributes.categories.alphaMountain.ai | string | | File Sharing/Storage, Search Engines/Portals |
action_result.data.\*.attributes.first_submission_date | numeric | | 1618399455 |
action_result.data.\*.attributes.last_analysis_date | numeric | | 1618399455 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | harmless |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CRDF |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | clean |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | Symantec |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | 78 |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | 1 |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | 8 |
action_result.data.\*.attributes.last_final_url | string | | https://www.test.com |
action_result.data.\*.attributes.last_http_response_code | numeric | | 200 |
action_result.data.\*.attributes.last_http_response_content_length | numeric | | 154896 |
action_result.data.\*.attributes.last_http_response_content_sha256 | string | | 9999993534b9c77669d1ebc821aed90fb34e31b587a4df32eba708193b25770d9 |
action_result.data.\*.attributes.last_http_response_cookies.\* | string | | xyz |
action_result.data.\*.attributes.last_http_response_cookies.PROMO | string | | ltv_pid=&ltv_new=1&ltv_ts=1659707757&ltv_sts=1659707757&ltv_c=1 |
action_result.data.\*.attributes.last_http_response_headers.\* | string | | same-origin-allow-popups; report-to="TestUi" |
action_result.data.\*.attributes.last_http_response_headers.Accept-CH | string | | Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64 |
action_result.data.\*.attributes.last_http_response_headers.Accept-Ranges | string | | bytes |
action_result.data.\*.attributes.last_http_response_headers.Age | string | | 0 |
action_result.data.\*.attributes.last_http_response_headers.Alt-Svc | string | | h3=":443"; ma=2592000,h3-29=":443"; ma=2592000 |
action_result.data.\*.attributes.last_http_response_headers.Cache-Control | string | | max-age=3600 |
action_result.data.\*.attributes.last_http_response_headers.Connection | string | | keep-alive |
action_result.data.\*.attributes.last_http_response_headers.Content-Encoding | string | | gzip |
action_result.data.\*.attributes.last_http_response_headers.Content-Length | string | | 17018 |
action_result.data.\*.attributes.last_http_response_headers.Content-Security-Policy | string | | upgrade-insecure-requests |
action_result.data.\*.attributes.last_http_response_headers.Content-Security-Policy-Report-Only | string | | object-src 'none';base-uri 'self';script-src 'nonce-foInPZdOHkO_qcMKb-VGOQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp |
action_result.data.\*.attributes.last_http_response_headers.Content-Type | string | | text/html |
action_result.data.\*.attributes.last_http_response_headers.Cross-Origin-Opener-Policy | string | | same-origin-allow-popups; report-to="gws" |
action_result.data.\*.attributes.last_http_response_headers.Date | string | | Thu, 09 Mar 2023 15:15:29 GMT |
action_result.data.\*.attributes.last_http_response_headers.ETag | string | | "128ff-5f63ddbca4199-gzip" |
action_result.data.\*.attributes.last_http_response_headers.Expect-CT | string | | max-age=31536000, enforce |
action_result.data.\*.attributes.last_http_response_headers.Expires | string | | Thu, 09 Mar 2023 16:15:29 GMT |
action_result.data.\*.attributes.last_http_response_headers.Last-Modified | string | | Mon, 06 Mar 2023 16:33:44 GMT |
action_result.data.\*.attributes.last_http_response_headers.Origin-Trial | string | | INVALIDzJDKSmEHjzM5ilaa908GuehlLqGb6ezME5lkhelj20qVzfv06zPmQ3LodoeujZuphAolrnhnPA8w4AIAAABfeyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJQZXJtaXNzaW9uc1BvbGljeVVubG9hZCIsImV4cGlyeSI6MTY4NTY2Mzk5OX0=, AvudrjMZqL7335p1KLV2lHo1kxdMeIN0dUI15d0CPz9dovVLCcXk8OAqjho1DX4s6NbHbA/AGobuGvcZv0drGgQAAAB9eyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJCYWNrRm9yd2FyZENhY2hlTm90UmVzdG9yZWRSZWFzb25zIiwiZXhwaXJ5IjoxNjkxNTM5MTk5LCJpc1N1YmRvbWFpbiI6dHJ1ZX0= |
action_result.data.\*.attributes.last_http_response_headers.P3P | string | | CP="This is not a P3P policy! See g.co/p3phelp for more info." |
action_result.data.\*.attributes.last_http_response_headers.Permissions-Policy | string | | unload=() |
action_result.data.\*.attributes.last_http_response_headers.Referrer-Policy | string | | no-referrer-when-downgrade |
action_result.data.\*.attributes.last_http_response_headers.Report-To | string | | {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]} |
action_result.data.\*.attributes.last_http_response_headers.Server | string | | Apache |
action_result.data.\*.attributes.last_http_response_headers.Set-Cookie | string | | INVALID5C560DE64992FF6A94E58729B071419B~YAAQF2IoF7fTtMaGAQAA7gPxxhMyDlfEQK6o6b1VDHh1A4q7gOyp9YKRW51LAjP8LNLyqBS/9X6QK+AWS6ji46AVd+P+YXEK4v2we6cMotyCTXPzSUeR8t7BgwzZdHpKYKw9cguU5OG7DKzGjMPKAYE3AohEOjvVqmHvQZYibzr2FQq0SpEUsTb9TBQHmdKYEMNAmpe7Xlet1DBBK4XAjdRZM0k9C37TCf82HkTnImuoQ/V5guyPnZqiKrlT~1; Domain=.ibm.com; Path=/; Expires=Thu, 09 Mar 2023 17:15:29 GMT; Max-Age=7200; Secure |
action_result.data.\*.attributes.last_http_response_headers.Strict-Transport-Security | string | | max-age=31536000 |
action_result.data.\*.attributes.last_http_response_headers.Transfer-Encoding | string | | chunked |
action_result.data.\*.attributes.last_http_response_headers.Vary | string | | Accept-Encoding |
action_result.data.\*.attributes.last_http_response_headers.X-Akamai-Transformed | string | | 9 16829 0 pmb=mTOE,2 |
action_result.data.\*.attributes.last_http_response_headers.X-Content-Type-Options | string | | nosniff |
action_result.data.\*.attributes.last_http_response_headers.X-Frame-Options | string | | SAMEORIGIN |
action_result.data.\*.attributes.last_http_response_headers.X-XSS-Protection | string | | 1; mode=block |
action_result.data.\*.attributes.last_http_response_headers.cache-control | string | | private |
action_result.data.\*.attributes.last_http_response_headers.content-encoding | string | | gzip |
action_result.data.\*.attributes.last_http_response_headers.content-length | string | | 18923 |
action_result.data.\*.attributes.last_http_response_headers.content-type | string | | text/html; charset=UTF-8 |
action_result.data.\*.attributes.last_http_response_headers.date | string | | Fri, 05 Aug 2022 13:55:57 GMT |
action_result.data.\*.attributes.last_http_response_headers.p3p | string | | policyref="https://policies.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV" |
action_result.data.\*.attributes.last_http_response_headers.secure_search_bypass | string | | true |
action_result.data.\*.attributes.last_http_response_headers.server | string | | ATS |
action_result.data.\*.attributes.last_http_response_headers.set-cookie | string | | PROMO=ltv_pid=&ltv_new=1&ltv_ts=1659707757&ltv_sts=1659707757&ltv_c=1; expires=Sat, 05-Aug-2023 13:55:57 GMT; Max-Age=31536000; path=/; domain=.search.yahoo.com |
action_result.data.\*.attributes.last_http_response_headers.vary | string | | Accept-Encoding |
action_result.data.\*.attributes.last_http_response_headers.x-content-type-options | string | | nosniff |
action_result.data.\*.attributes.last_http_response_headers.x-envoy-upstream-service-time | string | | 40 |
action_result.data.\*.attributes.last_http_response_headers.x-frame-options | string | | DENY |
action_result.data.\*.attributes.last_modification_date | numeric | | 1618399456 |
action_result.data.\*.attributes.last_submission_date | numeric | | 1618399455 |
action_result.data.\*.attributes.reputation | numeric | | 0 |
action_result.data.\*.attributes.times_submitted | numeric | | 1 |
action_result.data.\*.attributes.title | string | | Test |
action_result.data.\*.attributes.tld | string | | com |
action_result.data.\*.attributes.total_votes.harmless | numeric | | 0 |
action_result.data.\*.attributes.total_votes.malicious | numeric | | 0 |
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.id | string | | 7241469 |
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.timestamp | numeric | | 1627544121 |
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.url | string | | https://sb.scorecardresearch.com/p?c1=2&c2=7241469&c7=https%3A%2F%2Fin.yahoo.com%2F&c5=97684142&cv=2.0&cj=1&c14=-1 |
action_result.data.\*.attributes.trackers.Yahoo Dot Tags.\*.timestamp | numeric | | 1627544121 |
action_result.data.\*.attributes.trackers.Yahoo Dot Tags.\*.url | string | | https://s.yimg.com/rq/darla/4-6-0/js/g-r-min.js |
action_result.data.\*.attributes.url | string | | https://www.test.com |
action_result.data.\*.id | string | | 99999999eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 |
action_result.data.\*.links.self | string | | https://www.virustotal.com/api/v3/urls/e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 |
action_result.data.\*.type | string | | url |
action_result.summary.harmless | numeric | | 80 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.scan_id | string | `virustotal scan id` | 999999999b1b9c9999ca75016e4c010bc94836366881b021a658ea7f8548b6543c1e |
action_result.summary.source | string | | new from virustotal |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 9 |
action_result.message | string | | Scan id: u-9999999718dd52151f0e6fea2ff6fbf12d68a11046ba4ea3258546906c74f-1613644669, Harmless: 74, Malicious: 0, Suspicious: 0, Undetected: 9 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Load a URL to Virus Total and retrieve analysis results

Type: **investigate** \
Read only: **True**

<b>detonate url</b> will send a URL to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given URL has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to detonate | string | `url` `domain` |
**wait_time** | optional | Number of seconds to wait | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` `domain` | https://www.123test.com |
action_result.parameter.wait_time | numeric | | 10 |
action_result.data.\*.attributes.categories.\* | string | | searchengines |
action_result.data.\*.attributes.categories.BitDefender | string | | computersandsoftware |
action_result.data.\*.attributes.categories.Comodo Valkyrie Verdict | string | | content server |
action_result.data.\*.attributes.categories.Dr.Web | string | | e-mail |
action_result.data.\*.attributes.categories.Forcepoint ThreatSeeker | string | | search engines and portals |
action_result.data.\*.attributes.categories.Sophos | string | | portal sites |
action_result.data.\*.attributes.categories.Webroot | string | | Malware Sites |
action_result.data.\*.attributes.categories.Xcitium Verdict Cloud | string | | mobile communications |
action_result.data.\*.attributes.categories.alphaMountain.ai | string | | Business/Economy |
action_result.data.\*.attributes.first_submission_date | numeric | | 1618399455 |
action_result.data.\*.attributes.last_analysis_date | numeric | | 1618399455 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | harmless |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CRDF |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | clean |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | Symantec |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | 78 |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | 1 |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | 8 |
action_result.data.\*.attributes.last_final_url | string | | https://www.test.com |
action_result.data.\*.attributes.last_http_response_code | numeric | | 200 |
action_result.data.\*.attributes.last_http_response_content_length | numeric | | 154896 |
action_result.data.\*.attributes.last_http_response_content_sha256 | string | | e84603534b9c77669d1ebc821aed90fb34e31b587a4df32eba708193b25770d9 |
action_result.data.\*.attributes.last_http_response_cookies.\* | string | | xyz |
action_result.data.\*.attributes.last_http_response_cookies.\_\_cfduid | string | | dd6592227142b1c1144b4b4ff3ea1a8a91572286127 |
action_result.data.\*.attributes.last_http_response_headers.\* | string | | same-origin-allow-popups; report-to="TestUi" |
action_result.data.\*.attributes.last_http_response_headers.Accept-CH | string | | Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64 |
action_result.data.\*.attributes.last_http_response_headers.Access-Control-Allow-Origin | string | | * |
action_result.data.\*.attributes.last_http_response_headers.Age | string | | 0 |
action_result.data.\*.attributes.last_http_response_headers.Alt-Svc | string | | h3=":443"; ma=2592000,h3-29=":443"; ma=2592000 |
action_result.data.\*.attributes.last_http_response_headers.CF-Cache-Status | string | | DYNAMIC |
action_result.data.\*.attributes.last_http_response_headers.CF-RAY | string | | 7d1c90339ff22bb3-ORD |
action_result.data.\*.attributes.last_http_response_headers.Cache-Control | string | | no-store, no-cache, max-age=0, private |
action_result.data.\*.attributes.last_http_response_headers.Connection | string | | keep-alive |
action_result.data.\*.attributes.last_http_response_headers.Content-Encoding | string | | gzip |
action_result.data.\*.attributes.last_http_response_headers.Content-Security-Policy | string | | frame-ancestors 'self' https://\*.builtbygirls.com https://\*.rivals.com https://\*.engadget.com https://\*.intheknow.com https://\*.autoblog.com https://\*.techcrunch.com https://\*.yahoo.com https://\*.aol.com https://\*.huffingtonpost.com https://\*.oath.com https://\*.search.yahoo.com https://\*.pnr.ouryahoo.com https://pnr.ouryahoo.com https://\*.search.aol.com https://\*.search.huffpost.com https://\*.onesearch.com https://\*.verizonmedia.com https://\*.publishing.oath.com https://\*.autoblog.com; sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox allow-presentation; report-uri https://csp.yahoo.com/beacon/csp?src=ats&site=frontpage&region=US&lang=en-US&device=smartphone&yrid=7h2ptmphvv9rl&partner=; |
action_result.data.\*.attributes.last_http_response_headers.Content-Security-Policy-Report-Only | string | | object-src 'none';base-uri 'self';script-src 'nonce-qGMKc53CjVAFzzZ8RUEtnA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp |
action_result.data.\*.attributes.last_http_response_headers.Content-Type | string | | text/html; charset=UTF-8 |
action_result.data.\*.attributes.last_http_response_headers.Cross-Origin-Opener-Policy | string | | same-origin-allow-popups; report-to="gws" |
action_result.data.\*.attributes.last_http_response_headers.Cross-Origin-Opener-Policy-Report-Only | string | | same-origin; report-to="AccountsSignInUi" |
action_result.data.\*.attributes.last_http_response_headers.Cross-Origin-Resource-Policy | string | | same-site |
action_result.data.\*.attributes.last_http_response_headers.Date | string | | Tue, 21 Mar 2023 12:43:43 GMT |
action_result.data.\*.attributes.last_http_response_headers.ETag | string | | "7cVmZQ" |
action_result.data.\*.attributes.last_http_response_headers.Expires | string | | -1 |
action_result.data.\*.attributes.last_http_response_headers.Link | string | | <https://hii.com/wp-json/>; rel="https://api.w.org/", <https://hii.com/wp-json/wp/v2/pages/8298>; rel="alternate"; type="application/json", <https://hii.com/>; rel=shortlink |
action_result.data.\*.attributes.last_http_response_headers.Origin-Trial | string | | 999999999DKSmEHjzM5ilaa908GuehlLqGb6ezME5lkhelj20qVzfv06zPmQ3LodoeujZuphAolrnhnPA8w4AIAAABfeyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJQZXJtaXNzaW9uc1BvbGljeVVubG9hZCIsImV4cGlyeSI6MTY4NTY2Mzk5OX0=, AvudrjMZqL7335p1KLV2lHo1kxdMeIN0dUI15d0CPz9dovVLCcXk8OAqjho1DX4s6NbHbA/AGobuGvcZv0drGgQAAAB9eyJvcmlnaW4iOiJodHRwczovL3d3dy5nb29nbGUuY29tOjQ0MyIsImZlYXR1cmUiOiJCYWNrRm9yd2FyZENhY2hlTm90UmVzdG9yZWRSZWFzb25zIiwiZXhwaXJ5IjoxNjkxNTM5MTk5LCJpc1N1YmRvbWFpbiI6dHJ1ZX0= |
action_result.data.\*.attributes.last_http_response_headers.P3P | string | | CP="This is not a P3P policy! See g.co/p3phelp for more info." |
action_result.data.\*.attributes.last_http_response_headers.Permissions-Policy | string | | unload=() |
action_result.data.\*.attributes.last_http_response_headers.Pragma | string | | no-cache |
action_result.data.\*.attributes.last_http_response_headers.Report-To | string | | {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]} |
action_result.data.\*.attributes.last_http_response_headers.Server | string | | gws |
action_result.data.\*.attributes.last_http_response_headers.Set-Cookie | string | | 1P_JAR=2023-03-21-12; expires=Thu, 20-Apr-2023 12:43:43 GMT; path=/; domain=.google.com; Secure; SameSite=none, NID=511=uSBKYmXpnAMHRYvebOLMDNVKuXQVvO8Q-3eHs2Zjj6RhQwWNjU-j04Ysj_9pykK6S60UsbRbhRODW4_ywypZCL6j8dpbVFNJR5Ig-zy7qkEka26Oq-DpJdeV4XPWPVmg-dB6AXJJA6goK0QcMAiqPZK7OanyPrB1fY06uc9zreA; expires=Wed, 20-Sep-2023 12:43:43 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none |
action_result.data.\*.attributes.last_http_response_headers.Strict-Transport-Security | string | | max-age=31536000 |
action_result.data.\*.attributes.last_http_response_headers.Transfer-Encoding | string | | chunked |
action_result.data.\*.attributes.last_http_response_headers.Vary | string | | Accept-Encoding, Accept-Encoding, Accept-Encoding |
action_result.data.\*.attributes.last_http_response_headers.X-Cache | string | | HIT: 9 |
action_result.data.\*.attributes.last_http_response_headers.X-Cache-Group | string | | bot-mobile |
action_result.data.\*.attributes.last_http_response_headers.X-Cacheable | string | | bot |
action_result.data.\*.attributes.last_http_response_headers.X-Cloud-Trace-Context | string | | 9999999fda4db85ed68e4e34e7aefac6 |
action_result.data.\*.attributes.last_http_response_headers.X-Content-Type-Options | string | | nosniff |
action_result.data.\*.attributes.last_http_response_headers.X-Frame-Options | string | | SAMEORIGIN |
action_result.data.\*.attributes.last_http_response_headers.X-Powered-By | string | | WP Engine |
action_result.data.\*.attributes.last_http_response_headers.X-XSS-Protection | string | | 0 |
action_result.data.\*.attributes.last_http_response_headers.access-control-allow-origin | string | | * |
action_result.data.\*.attributes.last_http_response_headers.alt-svc | string | | h3=":443"; ma=86400 |
action_result.data.\*.attributes.last_http_response_headers.cf-ray | string | | 52cedb66e8b6c53c-ORD |
action_result.data.\*.attributes.last_http_response_headers.connection | string | | keep-alive |
action_result.data.\*.attributes.last_http_response_headers.content-encoding | string | | gzip |
action_result.data.\*.attributes.last_http_response_headers.content-length | string | | 15 |
action_result.data.\*.attributes.last_http_response_headers.content-type | string | | text/html; charset=utf-8 |
action_result.data.\*.attributes.last_http_response_headers.date | string | | Wed, 01 Mar 2023 19:28:53 GMT |
action_result.data.\*.attributes.last_http_response_headers.expect-ct | string | | max-age=31536000, report-uri="http://csp.yahoo.com/beacon/csp?src=yahoocom-expect-ct-report-only" |
action_result.data.\*.attributes.last_http_response_headers.keep-alive | string | | timeout=5, max=100 |
action_result.data.\*.attributes.last_http_response_headers.referrer-policy | string | | no-referrer-when-downgrade |
action_result.data.\*.attributes.last_http_response_headers.server | string | | ATS |
action_result.data.\*.attributes.last_http_response_headers.set-cookie | string | | \_\_cfduid=99999997142b1c1144b4b4ff3ea1a8a91572286127; expires=Tue, 27-Oct-20 18:08:47 GMT; path=/; domain=.ipinfo.in; HttpOnly; Secure |
action_result.data.\*.attributes.last_http_response_headers.strict-transport-security | string | | max-age=31536000 |
action_result.data.\*.attributes.last_http_response_headers.vary | string | | User-Agent |
action_result.data.\*.attributes.last_http_response_headers.x-content-type-options | string | | nosniff |
action_result.data.\*.attributes.last_http_response_headers.x-envoy-upstream-service-time | string | | 54 |
action_result.data.\*.attributes.last_http_response_headers.x-frame-options | string | | SAMEORIGIN |
action_result.data.\*.attributes.last_http_response_headers.x-powered-by | string | | PHP/7.4.29, PleskLin |
action_result.data.\*.attributes.last_http_response_headers.x-ua-compatible | string | | IE=edge |
action_result.data.\*.attributes.last_http_response_headers.x-xss-protection | string | | 1; mode=block |
action_result.data.\*.attributes.last_modification_date | numeric | | 1618399456 |
action_result.data.\*.attributes.last_submission_date | numeric | | 1618399455 |
action_result.data.\*.attributes.reputation | numeric | | 0 |
action_result.data.\*.attributes.times_submitted | numeric | | 1 |
action_result.data.\*.attributes.title | string | | Test |
action_result.data.\*.attributes.tld | string | | com |
action_result.data.\*.attributes.total_votes.harmless | numeric | | 0 |
action_result.data.\*.attributes.total_votes.malicious | numeric | | 0 |
action_result.data.\*.attributes.trackers.Doubleclick.\*.timestamp | numeric | | 1664533059 |
action_result.data.\*.attributes.trackers.Doubleclick.\*.url | string | | |
action_result.data.\*.attributes.trackers.Google Publisher Tags.\*.timestamp | numeric | | 1677698931 |
action_result.data.\*.attributes.trackers.Google Publisher Tags.\*.url | string | | https://securepubads.g.doubleclick.net/tag/js/gpt.js |
action_result.data.\*.attributes.trackers.Google Tag Manager.\*.id | string | | G-PTR82E305T |
action_result.data.\*.attributes.trackers.Google Tag Manager.\*.timestamp | numeric | | 1685843825 |
action_result.data.\*.attributes.trackers.Google Tag Manager.\*.url | string | | https://www.googletagmanager.com/gtag/js?id=G-PTR82E305T |
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.id | string | | 7241469 |
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.timestamp | numeric | | 1677698931 |
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.url | string | | https://sb.scorecardresearch.com/p?c1=2&c2=7241469&c5=1197228339&c7=https%3A%2F%2Fwww.yahoo.com%2F&c14=-1 |
action_result.data.\*.attributes.trackers.Yahoo Dot Tags.\*.timestamp | numeric | | 1677698931 |
action_result.data.\*.attributes.trackers.Yahoo Dot Tags.\*.url | string | | https://s.yimg.com/ss/rapid-3.53.38.js |
action_result.data.\*.attributes.url | string | | https://www.test.com |
action_result.data.\*.data.attributes.date | numeric | | 1613648861 |
action_result.data.\*.data.attributes.results.\*.category | string | | harmless |
action_result.data.\*.data.attributes.results.\*.engine_name | string | | CRDF |
action_result.data.\*.data.attributes.results.\*.method | string | | blacklist |
action_result.data.\*.data.attributes.results.\*.result | string | | clean |
action_result.data.\*.data.attributes.results.0xSI_f33d.category | string | | undetected |
action_result.data.\*.data.attributes.results.0xSI_f33d.engine_name | string | | 0xSI_f33d |
action_result.data.\*.data.attributes.results.0xSI_f33d.method | string | | blacklist |
action_result.data.\*.data.attributes.results.0xSI_f33d.result | string | | unrated |
action_result.data.\*.data.attributes.results.ADMINUSLabs.category | string | | harmless |
action_result.data.\*.data.attributes.results.ADMINUSLabs.engine_name | string | | ADMINUSLabs |
action_result.data.\*.data.attributes.results.ADMINUSLabs.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ADMINUSLabs.result | string | | clean |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).category | string | | harmless |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).engine_name | string | | AICC (MONITORAPP) |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).method | string | | blacklist |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).result | string | | clean |
action_result.data.\*.data.attributes.results.Abusix.category | string | | harmless |
action_result.data.\*.data.attributes.results.Abusix.engine_name | string | | Abusix |
action_result.data.\*.data.attributes.results.Abusix.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Abusix.result | string | | clean |
action_result.data.\*.data.attributes.results.Acronis.category | string | | harmless |
action_result.data.\*.data.attributes.results.Acronis.engine_name | string | | Acronis |
action_result.data.\*.data.attributes.results.Acronis.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Acronis.result | string | | clean |
action_result.data.\*.data.attributes.results.AlienVault.category | string | | harmless |
action_result.data.\*.data.attributes.results.AlienVault.engine_name | string | | AlienVault |
action_result.data.\*.data.attributes.results.AlienVault.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AlienVault.result | string | | clean |
action_result.data.\*.data.attributes.results.AlphaSOC.category | string | | undetected |
action_result.data.\*.data.attributes.results.AlphaSOC.engine_name | string | | AlphaSOC |
action_result.data.\*.data.attributes.results.AlphaSOC.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AlphaSOC.result | string | | unrated |
action_result.data.\*.data.attributes.results.Antiy-AVL.category | string | | harmless |
action_result.data.\*.data.attributes.results.Antiy-AVL.engine_name | string | | Antiy-AVL |
action_result.data.\*.data.attributes.results.Antiy-AVL.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Antiy-AVL.result | string | | clean |
action_result.data.\*.data.attributes.results.ArcSight Threat Intelligence.category | string | | undetected |
action_result.data.\*.data.attributes.results.ArcSight Threat Intelligence.engine_name | string | | ArcSight Threat Intelligence |
action_result.data.\*.data.attributes.results.ArcSight Threat Intelligence.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ArcSight Threat Intelligence.result | string | | unrated |
action_result.data.\*.data.attributes.results.Artists Against 419.category | string | | harmless |
action_result.data.\*.data.attributes.results.Artists Against 419.engine_name | string | | Artists Against 419 |
action_result.data.\*.data.attributes.results.Artists Against 419.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Artists Against 419.result | string | | clean |
action_result.data.\*.data.attributes.results.AutoShun.category | string | | undetected |
action_result.data.\*.data.attributes.results.AutoShun.engine_name | string | | AutoShun |
action_result.data.\*.data.attributes.results.AutoShun.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AutoShun.result | string | | unrated |
action_result.data.\*.data.attributes.results.Avira.category | string | | harmless |
action_result.data.\*.data.attributes.results.Avira.engine_name | string | | Avira |
action_result.data.\*.data.attributes.results.Avira.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Avira.result | string | | clean |
action_result.data.\*.data.attributes.results.Bfore.Ai PreCrime.category | string | | harmless |
action_result.data.\*.data.attributes.results.Bfore.Ai PreCrime.engine_name | string | | Bfore.Ai PreCrime |
action_result.data.\*.data.attributes.results.Bfore.Ai PreCrime.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Bfore.Ai PreCrime.result | string | | clean |
action_result.data.\*.data.attributes.results.BitDefender.category | string | | harmless |
action_result.data.\*.data.attributes.results.BitDefender.engine_name | string | | BitDefender |
action_result.data.\*.data.attributes.results.BitDefender.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BitDefender.result | string | | clean |
action_result.data.\*.data.attributes.results.Bkav.category | string | | undetected |
action_result.data.\*.data.attributes.results.Bkav.engine_name | string | | Bkav |
action_result.data.\*.data.attributes.results.Bkav.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Bkav.result | string | | unrated |
action_result.data.\*.data.attributes.results.BlockList.category | string | | harmless |
action_result.data.\*.data.attributes.results.BlockList.engine_name | string | | BlockList |
action_result.data.\*.data.attributes.results.BlockList.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BlockList.result | string | | clean |
action_result.data.\*.data.attributes.results.Blueliv.category | string | | harmless |
action_result.data.\*.data.attributes.results.Blueliv.engine_name | string | | Blueliv |
action_result.data.\*.data.attributes.results.Blueliv.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Blueliv.result | string | | clean |
action_result.data.\*.data.attributes.results.CINS Army.category | string | | harmless |
action_result.data.\*.data.attributes.results.CINS Army.engine_name | string | | CINS Army |
action_result.data.\*.data.attributes.results.CINS Army.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CINS Army.result | string | | clean |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.category | string | | harmless |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.engine_name | string | | CMC Threat Intelligence |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.result | string | | clean |
action_result.data.\*.data.attributes.results.CRDF.category | string | | harmless |
action_result.data.\*.data.attributes.results.CRDF.engine_name | string | | CRDF |
action_result.data.\*.data.attributes.results.CRDF.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CRDF.result | string | | clean |
action_result.data.\*.data.attributes.results.Certego.category | string | | harmless |
action_result.data.\*.data.attributes.results.Certego.engine_name | string | | Certego |
action_result.data.\*.data.attributes.results.Certego.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Certego.result | string | | clean |
action_result.data.\*.data.attributes.results.Chong Lua Dao.category | string | | harmless |
action_result.data.\*.data.attributes.results.Chong Lua Dao.engine_name | string | | Chong Lua Dao |
action_result.data.\*.data.attributes.results.Chong Lua Dao.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Chong Lua Dao.result | string | | clean |
action_result.data.\*.data.attributes.results.Cluster25.category | string | | undetected |
action_result.data.\*.data.attributes.results.Cluster25.engine_name | string | | Cluster25 |
action_result.data.\*.data.attributes.results.Cluster25.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cluster25.result | string | | unrated |
action_result.data.\*.data.attributes.results.Criminal IP.category | string | | undetected |
action_result.data.\*.data.attributes.results.Criminal IP.engine_name | string | | Criminal IP |
action_result.data.\*.data.attributes.results.Criminal IP.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Criminal IP.result | string | | unrated |
action_result.data.\*.data.attributes.results.CrowdSec.category | string | | undetected |
action_result.data.\*.data.attributes.results.CrowdSec.engine_name | string | | CrowdSec |
action_result.data.\*.data.attributes.results.CrowdSec.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CrowdSec.result | string | | unrated |
action_result.data.\*.data.attributes.results.CyRadar.category | string | | harmless |
action_result.data.\*.data.attributes.results.CyRadar.engine_name | string | | CyRadar |
action_result.data.\*.data.attributes.results.CyRadar.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CyRadar.result | string | | clean |
action_result.data.\*.data.attributes.results.Cyan.category | string | | undetected |
action_result.data.\*.data.attributes.results.Cyan.engine_name | string | | Cyan |
action_result.data.\*.data.attributes.results.Cyan.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cyan.result | string | | unrated |
action_result.data.\*.data.attributes.results.Cyble.category | string | | harmless |
action_result.data.\*.data.attributes.results.Cyble.engine_name | string | | Cyble |
action_result.data.\*.data.attributes.results.Cyble.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cyble.result | string | | clean |
action_result.data.\*.data.attributes.results.DNS8.category | string | | harmless |
action_result.data.\*.data.attributes.results.DNS8.engine_name | string | | DNS8 |
action_result.data.\*.data.attributes.results.DNS8.method | string | | blacklist |
action_result.data.\*.data.attributes.results.DNS8.result | string | | clean |
action_result.data.\*.data.attributes.results.Dr.Web.category | string | | harmless |
action_result.data.\*.data.attributes.results.Dr.Web.engine_name | string | | Dr.Web |
action_result.data.\*.data.attributes.results.Dr.Web.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Dr.Web.result | string | | clean |
action_result.data.\*.data.attributes.results.ESET.category | string | | harmless |
action_result.data.\*.data.attributes.results.ESET.engine_name | string | | ESET |
action_result.data.\*.data.attributes.results.ESET.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ESET.result | string | | clean |
action_result.data.\*.data.attributes.results.ESTsecurity.category | string | | harmless |
action_result.data.\*.data.attributes.results.ESTsecurity.engine_name | string | | ESTsecurity |
action_result.data.\*.data.attributes.results.ESTsecurity.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ESTsecurity.result | string | | clean |
action_result.data.\*.data.attributes.results.EmergingThreats.category | string | | harmless |
action_result.data.\*.data.attributes.results.EmergingThreats.engine_name | string | | EmergingThreats |
action_result.data.\*.data.attributes.results.EmergingThreats.method | string | | blacklist |
action_result.data.\*.data.attributes.results.EmergingThreats.result | string | | clean |
action_result.data.\*.data.attributes.results.Emsisoft.category | string | | harmless |
action_result.data.\*.data.attributes.results.Emsisoft.engine_name | string | | Emsisoft |
action_result.data.\*.data.attributes.results.Emsisoft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Emsisoft.result | string | | clean |
action_result.data.\*.data.attributes.results.Feodo Tracker.category | string | | harmless |
action_result.data.\*.data.attributes.results.Feodo Tracker.engine_name | string | | Feodo Tracker |
action_result.data.\*.data.attributes.results.Feodo Tracker.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Feodo Tracker.result | string | | clean |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.category | string | | undetected |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.engine_name | string | | Forcepoint ThreatSeeker |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.result | string | | unrated |
action_result.data.\*.data.attributes.results.Fortinet.category | string | | harmless |
action_result.data.\*.data.attributes.results.Fortinet.engine_name | string | | Fortinet |
action_result.data.\*.data.attributes.results.Fortinet.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Fortinet.result | string | | clean |
action_result.data.\*.data.attributes.results.G-Data.category | string | | harmless |
action_result.data.\*.data.attributes.results.G-Data.engine_name | string | | G-Data |
action_result.data.\*.data.attributes.results.G-Data.method | string | | blacklist |
action_result.data.\*.data.attributes.results.G-Data.result | string | | clean |
action_result.data.\*.data.attributes.results.Google Safebrowsing.category | string | | harmless |
action_result.data.\*.data.attributes.results.Google Safebrowsing.engine_name | string | | Google Safebrowsing |
action_result.data.\*.data.attributes.results.Google Safebrowsing.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Google Safebrowsing.result | string | | clean |
action_result.data.\*.data.attributes.results.GreenSnow.category | string | | harmless |
action_result.data.\*.data.attributes.results.GreenSnow.engine_name | string | | GreenSnow |
action_result.data.\*.data.attributes.results.GreenSnow.method | string | | blacklist |
action_result.data.\*.data.attributes.results.GreenSnow.result | string | | clean |
action_result.data.\*.data.attributes.results.Heimdal Security.category | string | | harmless |
action_result.data.\*.data.attributes.results.Heimdal Security.engine_name | string | | Heimdal Security |
action_result.data.\*.data.attributes.results.Heimdal Security.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Heimdal Security.result | string | | clean |
action_result.data.\*.data.attributes.results.IPsum.category | string | | harmless |
action_result.data.\*.data.attributes.results.IPsum.engine_name | string | | IPsum |
action_result.data.\*.data.attributes.results.IPsum.method | string | | blacklist |
action_result.data.\*.data.attributes.results.IPsum.result | string | | clean |
action_result.data.\*.data.attributes.results.Juniper Networks.category | string | | harmless |
action_result.data.\*.data.attributes.results.Juniper Networks.engine_name | string | | Juniper Networks |
action_result.data.\*.data.attributes.results.Juniper Networks.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Juniper Networks.result | string | | clean |
action_result.data.\*.data.attributes.results.K7AntiVirus.category | string | | harmless |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_name | string | | K7AntiVirus |
action_result.data.\*.data.attributes.results.K7AntiVirus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.K7AntiVirus.result | string | | clean |
action_result.data.\*.data.attributes.results.Kaspersky.category | string | | undetected |
action_result.data.\*.data.attributes.results.Kaspersky.engine_name | string | | Kaspersky |
action_result.data.\*.data.attributes.results.Kaspersky.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Kaspersky.result | string | | unrated |
action_result.data.\*.data.attributes.results.Lionic.category | string | | harmless |
action_result.data.\*.data.attributes.results.Lionic.engine_name | string | | Lionic |
action_result.data.\*.data.attributes.results.Lionic.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Lionic.result | string | | clean |
action_result.data.\*.data.attributes.results.Lumu.category | string | | undetected |
action_result.data.\*.data.attributes.results.Lumu.engine_name | string | | Lumu |
action_result.data.\*.data.attributes.results.Lumu.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Lumu.result | string | | unrated |
action_result.data.\*.data.attributes.results.MalwarePatrol.category | string | | harmless |
action_result.data.\*.data.attributes.results.MalwarePatrol.engine_name | string | | MalwarePatrol |
action_result.data.\*.data.attributes.results.MalwarePatrol.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MalwarePatrol.result | string | | clean |
action_result.data.\*.data.attributes.results.Malwared.category | string | | harmless |
action_result.data.\*.data.attributes.results.Malwared.engine_name | string | | Malwared |
action_result.data.\*.data.attributes.results.Malwared.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Malwared.result | string | | clean |
action_result.data.\*.data.attributes.results.Netcraft.category | string | | undetected |
action_result.data.\*.data.attributes.results.Netcraft.engine_name | string | | Netcraft |
action_result.data.\*.data.attributes.results.Netcraft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Netcraft.result | string | | unrated |
action_result.data.\*.data.attributes.results.OpenPhish.category | string | | harmless |
action_result.data.\*.data.attributes.results.OpenPhish.engine_name | string | | OpenPhish |
action_result.data.\*.data.attributes.results.OpenPhish.method | string | | blacklist |
action_result.data.\*.data.attributes.results.OpenPhish.result | string | | clean |
action_result.data.\*.data.attributes.results.PREBYTES.category | string | | harmless |
action_result.data.\*.data.attributes.results.PREBYTES.engine_name | string | | PREBYTES |
action_result.data.\*.data.attributes.results.PREBYTES.method | string | | blacklist |
action_result.data.\*.data.attributes.results.PREBYTES.result | string | | clean |
action_result.data.\*.data.attributes.results.PhishFort.category | string | | undetected |
action_result.data.\*.data.attributes.results.PhishFort.engine_name | string | | PhishFort |
action_result.data.\*.data.attributes.results.PhishFort.method | string | | blacklist |
action_result.data.\*.data.attributes.results.PhishFort.result | string | | unrated |
action_result.data.\*.data.attributes.results.PhishLabs.category | string | | undetected |
action_result.data.\*.data.attributes.results.PhishLabs.engine_name | string | | PhishLabs |
action_result.data.\*.data.attributes.results.PhishLabs.method | string | | blacklist |
action_result.data.\*.data.attributes.results.PhishLabs.result | string | | unrated |
action_result.data.\*.data.attributes.results.Phishing Database.category | string | | harmless |
action_result.data.\*.data.attributes.results.Phishing Database.engine_name | string | | Phishing Database |
action_result.data.\*.data.attributes.results.Phishing Database.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Phishing Database.result | string | | clean |
action_result.data.\*.data.attributes.results.Phishtank.category | string | | harmless |
action_result.data.\*.data.attributes.results.Phishtank.engine_name | string | | Phishtank |
action_result.data.\*.data.attributes.results.Phishtank.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Phishtank.result | string | | clean |
action_result.data.\*.data.attributes.results.PrecisionSec.category | string | | undetected |
action_result.data.\*.data.attributes.results.PrecisionSec.engine_name | string | | PrecisionSec |
action_result.data.\*.data.attributes.results.PrecisionSec.method | string | | blacklist |
action_result.data.\*.data.attributes.results.PrecisionSec.result | string | | unrated |
action_result.data.\*.data.attributes.results.Quick Heal.category | string | | harmless |
action_result.data.\*.data.attributes.results.Quick Heal.engine_name | string | | Quick Heal |
action_result.data.\*.data.attributes.results.Quick Heal.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Quick Heal.result | string | | clean |
action_result.data.\*.data.attributes.results.Quttera.category | string | | harmless |
action_result.data.\*.data.attributes.results.Quttera.engine_name | string | | Quttera |
action_result.data.\*.data.attributes.results.Quttera.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Quttera.result | string | | clean |
action_result.data.\*.data.attributes.results.Rising.category | string | | harmless |
action_result.data.\*.data.attributes.results.Rising.engine_name | string | | Rising |
action_result.data.\*.data.attributes.results.Rising.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Rising.result | string | | clean |
action_result.data.\*.data.attributes.results.SCUMWARE.org.category | string | | harmless |
action_result.data.\*.data.attributes.results.SCUMWARE.org.engine_name | string | | SCUMWARE.org |
action_result.data.\*.data.attributes.results.SCUMWARE.org.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SCUMWARE.org.result | string | | clean |
action_result.data.\*.data.attributes.results.SOCRadar.category | string | | undetected |
action_result.data.\*.data.attributes.results.SOCRadar.engine_name | string | | SOCRadar |
action_result.data.\*.data.attributes.results.SOCRadar.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SOCRadar.result | string | | unrated |
action_result.data.\*.data.attributes.results.SafeToOpen.category | string | | undetected |
action_result.data.\*.data.attributes.results.SafeToOpen.engine_name | string | | SafeToOpen |
action_result.data.\*.data.attributes.results.SafeToOpen.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SafeToOpen.result | string | | unrated |
action_result.data.\*.data.attributes.results.Sangfor.category | string | | harmless |
action_result.data.\*.data.attributes.results.Sangfor.engine_name | string | | Sangfor |
action_result.data.\*.data.attributes.results.Sangfor.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sangfor.result | string | | clean |
action_result.data.\*.data.attributes.results.Scantitan.category | string | | harmless |
action_result.data.\*.data.attributes.results.Scantitan.engine_name | string | | Scantitan |
action_result.data.\*.data.attributes.results.Scantitan.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Scantitan.result | string | | clean |
action_result.data.\*.data.attributes.results.Seclookup.category | string | | harmless |
action_result.data.\*.data.attributes.results.Seclookup.engine_name | string | | Seclookup |
action_result.data.\*.data.attributes.results.Seclookup.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Seclookup.result | string | | clean |
action_result.data.\*.data.attributes.results.SecureBrain.category | string | | harmless |
action_result.data.\*.data.attributes.results.SecureBrain.engine_name | string | | SecureBrain |
action_result.data.\*.data.attributes.results.SecureBrain.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SecureBrain.result | string | | clean |
action_result.data.\*.data.attributes.results.Snort IP sample list.category | string | | harmless |
action_result.data.\*.data.attributes.results.Snort IP sample list.engine_name | string | | Snort IP sample list |
action_result.data.\*.data.attributes.results.Snort IP sample list.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Snort IP sample list.result | string | | clean |
action_result.data.\*.data.attributes.results.Sophos.category | string | | harmless |
action_result.data.\*.data.attributes.results.Sophos.engine_name | string | | Sophos |
action_result.data.\*.data.attributes.results.Sophos.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sophos.result | string | | clean |
action_result.data.\*.data.attributes.results.Spam404.category | string | | harmless |
action_result.data.\*.data.attributes.results.Spam404.engine_name | string | | Spam404 |
action_result.data.\*.data.attributes.results.Spam404.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Spam404.result | string | | clean |
action_result.data.\*.data.attributes.results.StopForumSpam.category | string | | harmless |
action_result.data.\*.data.attributes.results.StopForumSpam.engine_name | string | | StopForumSpam |
action_result.data.\*.data.attributes.results.StopForumSpam.method | string | | blacklist |
action_result.data.\*.data.attributes.results.StopForumSpam.result | string | | clean |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.category | string | | harmless |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.engine_name | string | | Sucuri SiteCheck |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.result | string | | clean |
action_result.data.\*.data.attributes.results.ThreatHive.category | string | | harmless |
action_result.data.\*.data.attributes.results.ThreatHive.engine_name | string | | ThreatHive |
action_result.data.\*.data.attributes.results.ThreatHive.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ThreatHive.result | string | | clean |
action_result.data.\*.data.attributes.results.Threatsourcing.category | string | | harmless |
action_result.data.\*.data.attributes.results.Threatsourcing.engine_name | string | | Threatsourcing |
action_result.data.\*.data.attributes.results.Threatsourcing.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Threatsourcing.result | string | | clean |
action_result.data.\*.data.attributes.results.Trustwave.category | string | | harmless |
action_result.data.\*.data.attributes.results.Trustwave.engine_name | string | | Trustwave |
action_result.data.\*.data.attributes.results.Trustwave.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Trustwave.result | string | | clean |
action_result.data.\*.data.attributes.results.URLQuery.category | string | | undetected |
action_result.data.\*.data.attributes.results.URLQuery.engine_name | string | | URLQuery |
action_result.data.\*.data.attributes.results.URLQuery.method | string | | blacklist |
action_result.data.\*.data.attributes.results.URLQuery.result | string | | unrated |
action_result.data.\*.data.attributes.results.URLhaus.category | string | | harmless |
action_result.data.\*.data.attributes.results.URLhaus.engine_name | string | | URLhaus |
action_result.data.\*.data.attributes.results.URLhaus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.URLhaus.result | string | | clean |
action_result.data.\*.data.attributes.results.VIPRE.category | string | | undetected |
action_result.data.\*.data.attributes.results.VIPRE.engine_name | string | | VIPRE |
action_result.data.\*.data.attributes.results.VIPRE.method | string | | blacklist |
action_result.data.\*.data.attributes.results.VIPRE.result | string | | unrated |
action_result.data.\*.data.attributes.results.VX Vault.category | string | | harmless |
action_result.data.\*.data.attributes.results.VX Vault.engine_name | string | | VX Vault |
action_result.data.\*.data.attributes.results.VX Vault.method | string | | blacklist |
action_result.data.\*.data.attributes.results.VX Vault.result | string | | clean |
action_result.data.\*.data.attributes.results.Viettel Threat Intelligence.category | string | | harmless |
action_result.data.\*.data.attributes.results.Viettel Threat Intelligence.engine_name | string | | Viettel Threat Intelligence |
action_result.data.\*.data.attributes.results.Viettel Threat Intelligence.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Viettel Threat Intelligence.result | string | | clean |
action_result.data.\*.data.attributes.results.ViriBack.category | string | | harmless |
action_result.data.\*.data.attributes.results.ViriBack.engine_name | string | | ViriBack |
action_result.data.\*.data.attributes.results.ViriBack.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ViriBack.result | string | | clean |
action_result.data.\*.data.attributes.results.Webroot.category | string | | harmless |
action_result.data.\*.data.attributes.results.Webroot.engine_name | string | | Webroot |
action_result.data.\*.data.attributes.results.Webroot.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Webroot.result | string | | clean |
action_result.data.\*.data.attributes.results.Xcitium Verdict Cloud.category | string | | undetected |
action_result.data.\*.data.attributes.results.Xcitium Verdict Cloud.engine_name | string | | Xcitium Verdict Cloud |
action_result.data.\*.data.attributes.results.Xcitium Verdict Cloud.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Xcitium Verdict Cloud.result | string | | unrated |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.category | string | | harmless |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.engine_name | string | | Yandex Safebrowsing |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.result | string | | clean |
action_result.data.\*.data.attributes.results.ZeroCERT.category | string | | harmless |
action_result.data.\*.data.attributes.results.ZeroCERT.engine_name | string | | ZeroCERT |
action_result.data.\*.data.attributes.results.ZeroCERT.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ZeroCERT.result | string | | clean |
action_result.data.\*.data.attributes.results.alphaMountain.ai.category | string | | harmless |
action_result.data.\*.data.attributes.results.alphaMountain.ai.engine_name | string | | alphaMountain.ai |
action_result.data.\*.data.attributes.results.alphaMountain.ai.method | string | | blacklist |
action_result.data.\*.data.attributes.results.alphaMountain.ai.result | string | | clean |
action_result.data.\*.data.attributes.results.benkow.cc.category | string | | harmless |
action_result.data.\*.data.attributes.results.benkow.cc.engine_name | string | | benkow.cc |
action_result.data.\*.data.attributes.results.benkow.cc.method | string | | blacklist |
action_result.data.\*.data.attributes.results.benkow.cc.result | string | | clean |
action_result.data.\*.data.attributes.results.desenmascara.me.category | string | | harmless |
action_result.data.\*.data.attributes.results.desenmascara.me.engine_name | string | | desenmascara.me |
action_result.data.\*.data.attributes.results.desenmascara.me.method | string | | blacklist |
action_result.data.\*.data.attributes.results.desenmascara.me.result | string | | clean |
action_result.data.\*.data.attributes.results.malwares.com URL checker.category | string | | harmless |
action_result.data.\*.data.attributes.results.malwares.com URL checker.engine_name | string | | malwares.com URL checker |
action_result.data.\*.data.attributes.results.malwares.com URL checker.method | string | | blacklist |
action_result.data.\*.data.attributes.results.malwares.com URL checker.result | string | | clean |
action_result.data.\*.data.attributes.results.securolytics.category | string | | harmless |
action_result.data.\*.data.attributes.results.securolytics.engine_name | string | | securolytics |
action_result.data.\*.data.attributes.results.securolytics.method | string | | blacklist |
action_result.data.\*.data.attributes.results.securolytics.result | string | | clean |
action_result.data.\*.data.attributes.stats.harmless | numeric | | 76 |
action_result.data.\*.data.attributes.stats.malicious | numeric | | 0 |
action_result.data.\*.data.attributes.stats.suspicious | numeric | | 0 |
action_result.data.\*.data.attributes.stats.timeout | numeric | | 0 |
action_result.data.\*.data.attributes.stats.undetected | numeric | | 7 |
action_result.data.\*.data.attributes.status | string | | completed |
action_result.data.\*.data.id | string | `virustotal scan id` | u-e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761-1613648861 |
action_result.data.\*.data.links.item | string | | https://www.virustotal.com/api/v3/urls/5f08bb2001dfc7f3f2c2026038cfe2868a08b96eab48298d808a4008fafcb2aa |
action_result.data.\*.data.links.self | string | | https://www.virustotal.com/api/v3/analyses/u-5f08bb2001dfc7f3f2c2026038cfe2868a08b96eab48298d808a4008fafcb2aa-1684316846 |
action_result.data.\*.data.type | string | | analysis |
action_result.data.\*.id | string | | e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 |
action_result.data.\*.links.self | string | | https://www.virustotal.com/api/v3/urls/e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 |
action_result.data.\*.meta.url_info.id | string | `sha256` | e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761 |
action_result.data.\*.meta.url_info.url | string | `url` | https://www.123test.com/ |
action_result.data.\*.type | string | | url |
action_result.summary.harmless | numeric | | 80 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.scan_id | string | `virustotal scan id` | u-99999999999c9999ca75016e4c010bc94836366881b021a658ea7f8548b6543c1e |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 7 |
action_result.message | string | | Scan id: u-9999999999f67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761-1613648861, Harmless: 76, Malicious: 0, Suspicious: 0, Undetected: 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate file'

Upload a file to Virus Total and retrieve the analysis results

Type: **investigate** \
Read only: **True**

<b>detonate file</b> will send a file to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given file has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | The Vault ID of the file to scan | string | `vault id` `sha1` |
**wait_time** | optional | Number of seconds to wait | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.vault_id | string | `vault id` `sha1` | 99999999919142292710254cde97df84e46dfe33a |
action_result.parameter.wait_time | numeric | | 10 |
action_result.data.\*.attributes.androguard.AndroguardVersion | string | | 3.0-dev |
action_result.data.\*.attributes.androguard.AndroidApplication | numeric | | 1 |
action_result.data.\*.attributes.androguard.AndroidApplicationError | boolean | | False |
action_result.data.\*.attributes.androguard.AndroidApplicationInfo | string | | APK |
action_result.data.\*.attributes.androguard.AndroidVersionCode | string | | 1 |
action_result.data.\*.attributes.androguard.AndroidVersionName | string | | 1.0 |
action_result.data.\*.attributes.androguard.MinSdkVersion | string | | 11 |
action_result.data.\*.attributes.androguard.Package | string | | com.ibm.android.analyzer.test |
action_result.data.\*.attributes.androguard.RiskIndicator.APK.\* | numeric | | 1 |
action_result.data.\*.attributes.androguard.RiskIndicator.PERM.\* | numeric | | 1 |
action_result.data.\*.attributes.androguard.TargetSdkVersion | string | | 11 |
action_result.data.\*.attributes.androguard.VTAndroidInfo | numeric | | 1.41 |
action_result.data.\*.attributes.androguard.certificate.Issuer.\* | string | | C:US, CN:Android Debug, O:Android |
action_result.data.\*.attributes.androguard.certificate.Subject.\* | string | | US |
action_result.data.\*.attributes.androguard.certificate.serialnumber | string | | 6f20b2e6 |
action_result.data.\*.attributes.androguard.certificate.thumbprint | string | | 7bd81368b868225bde96fc1a3fee59a8ea06296a |
action_result.data.\*.attributes.androguard.certificate.validfrom | string | | 2016-01-27 08:46:16 |
action_result.data.\*.attributes.androguard.certificate.validto | string | | 2046-01-19 08:46:16 |
action_result.data.\*.attributes.androguard.main_activity | string | | com.ibm.android.analyzer.test.xas.CAS |
action_result.data.\*.attributes.androguard.permission_details.android.permission.\*.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.\*.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.\*.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.com.ibm.android.analyzer.test.\*.full_description | string | | Unknown permission from android reference |
action_result.data.\*.attributes.androguard.permission_details.com.ibm.android.analyzer.test.\*.permission_type | string | | normal |
action_result.data.\*.attributes.androguard.permission_details.com.ibm.android.analyzer.test.\*.short_description | string | | Unknown permission from android reference |
action_result.data.\*.attributes.authentihash | string | | 9999999999a601c12ac88d70736e5a5064dac716fe071ce9e3bb206d67b1b9a5 |
action_result.data.\*.attributes.bundle_info.extensions.\* | numeric | | 1 |
action_result.data.\*.attributes.bundle_info.file_types.\* | numeric | | 1 |
action_result.data.\*.attributes.bundle_info.highest_datetime | string | | 2019-01-03 12:33:40 |
action_result.data.\*.attributes.bundle_info.lowest_datetime | string | | 2019-01-03 12:33:40 |
action_result.data.\*.attributes.bundle_info.num_children | numeric | | 1 |
action_result.data.\*.attributes.bundle_info.type | string | | ZIP |
action_result.data.\*.attributes.bundle_info.uncompressed_size | numeric | | 481 |
action_result.data.\*.attributes.bytehero_info | string | | Trojan.Win32.Heur.Gen |
action_result.data.\*.attributes.creation_date | numeric | | 1539102614 |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.alert_severity | string | | medium |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_category | string | | Potentially Bad Traffic |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_id | string | | 1:2027865 |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_msg | string | | ET INFO Observed DNS Query to .cloud TLD |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_raw | string | | alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns.query; content:".cloud"; nocase; endswith; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027865; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2019_08_13, deployment Perimeter, former_category INFO, signature_severity Major, updated_at 2020_09_17;) |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_source | string | | Proofpoint Emerging Threats Open |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_url | string | | https://rules.emergingthreats.net/ |
action_result.data.\*.attributes.crowdsourced_ids_stats.\* | numeric | | 0 |
action_result.data.\*.attributes.first_seen_itw_date | numeric | | 1502111702 |
action_result.data.\*.attributes.first_submission_date | numeric | | 1612961082 |
action_result.data.\*.attributes.html_info.iframes.\*.attributes.\* | string | | ./test_html_files/list.html |
action_result.data.\*.attributes.html_info.scripts.\*.attributes.src | string | | ./test_html_files/exerc.js.download |
action_result.data.\*.attributes.last_analysis_date | numeric | | 1613635130 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | undetected |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.\*.engine_update | string | | 20210218 |
action_result.data.\*.attributes.last_analysis_results.\*.engine_version | string | | 2.10.2019.1 |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | Symantec |
action_result.data.\*.attributes.last_analysis_stats.confirmed-timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.failure | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | 0 |
action_result.data.\*.attributes.last_analysis_stats.type-unsupported | numeric | | 16 |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | 59 |
action_result.data.\*.attributes.last_modification_date | numeric | | 1613635210 |
action_result.data.\*.attributes.last_submission_date | numeric | | 1613635130 |
action_result.data.\*.attributes.magic | string | | a python2.7\\015script text executable |
action_result.data.\*.attributes.md5 | string | `md5` | 99999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.attributes.meaningful_name | string | | update_cr.py |
action_result.data.\*.attributes.names | string | | update_cr.py |
action_result.data.\*.attributes.packers.F-PROT | string | | appended, docwrite |
action_result.data.\*.attributes.pdf_info.\* | numeric | | 0 |
action_result.data.\*.attributes.pdf_info.acroform | numeric | | |
action_result.data.\*.attributes.pdf_info.autoaction | numeric | | |
action_result.data.\*.attributes.pdf_info.embedded_file | numeric | | |
action_result.data.\*.attributes.pdf_info.encrypted | numeric | | |
action_result.data.\*.attributes.pdf_info.flash | numeric | | |
action_result.data.\*.attributes.pdf_info.header | string | | %PDF-1.5 |
action_result.data.\*.attributes.pdf_info.javascript | numeric | | |
action_result.data.\*.attributes.pdf_info.jbig2_compression | numeric | | |
action_result.data.\*.attributes.pdf_info.js | numeric | | |
action_result.data.\*.attributes.pdf_info.num_endobj | numeric | | 29 |
action_result.data.\*.attributes.pdf_info.num_endstream | numeric | | 28 |
action_result.data.\*.attributes.pdf_info.num_launch_actions | numeric | | |
action_result.data.\*.attributes.pdf_info.num_obj | numeric | | 29 |
action_result.data.\*.attributes.pdf_info.num_object_streams | numeric | | 1 |
action_result.data.\*.attributes.pdf_info.num_pages | numeric | | |
action_result.data.\*.attributes.pdf_info.num_stream | numeric | | 28 |
action_result.data.\*.attributes.pdf_info.openaction | numeric | | |
action_result.data.\*.attributes.pdf_info.startxref | numeric | | 1 |
action_result.data.\*.attributes.pdf_info.suspicious_colors | numeric | | |
action_result.data.\*.attributes.pdf_info.trailer | numeric | | |
action_result.data.\*.attributes.pdf_info.xfa | numeric | | |
action_result.data.\*.attributes.pdf_info.xref | numeric | | |
action_result.data.\*.attributes.pe_info.entry_point | numeric | | 176128 |
action_result.data.\*.attributes.pe_info.imphash | string | | 6bff2c73afd9249c4261ecfba6ff33c3 |
action_result.data.\*.attributes.pe_info.import_list.\*.library_name | string | | MSVCP60.dll |
action_result.data.\*.attributes.pe_info.machine_type | numeric | | 332 |
action_result.data.\*.attributes.pe_info.overlay.\* | string | | xyz |
action_result.data.\*.attributes.pe_info.resource_details.\*.chi2 | numeric | | 33203.078125 |
action_result.data.\*.attributes.pe_info.resource_details.\*.entropy | numeric | | 1.802635908126831 |
action_result.data.\*.attributes.pe_info.resource_details.\*.filetype | string | | Data |
action_result.data.\*.attributes.pe_info.resource_details.\*.lang | string | | CHINESE SIMPLIFIED |
action_result.data.\*.attributes.pe_info.resource_details.\*.sha256 | string | | 9999999999f0f912228ae647d10e15a014b8ce40dd164fa30290913227d |
action_result.data.\*.attributes.pe_info.resource_details.\*.type | string | | RT_CURSOR |
action_result.data.\*.attributes.pe_info.resource_langs.CHINESE SIMPLIFIED | numeric | | 8 |
action_result.data.\*.attributes.pe_info.resource_types.RT_BITMAP | numeric | | 4 |
action_result.data.\*.attributes.pe_info.resource_types.RT_CURSOR | numeric | | 1 |
action_result.data.\*.attributes.pe_info.resource_types.RT_GROUP_CURSOR | numeric | | 1 |
action_result.data.\*.attributes.pe_info.resource_types.RT_MENU | numeric | | 1 |
action_result.data.\*.attributes.pe_info.resource_types.RT_VERSION | numeric | | 1 |
action_result.data.\*.attributes.pe_info.rich_pe_header_hash | string | | 9999999999167a185aba138b2846e0b906 |
action_result.data.\*.attributes.pe_info.sections.\*.chi2 | numeric | | 672207.13 |
action_result.data.\*.attributes.pe_info.sections.\*.entropy | numeric | | 6.46 |
action_result.data.\*.attributes.pe_info.sections.\*.flags | string | | rx |
action_result.data.\*.attributes.pe_info.sections.\*.md5 | string | | 999999999982ea3987560f91ce29f946f4 |
action_result.data.\*.attributes.pe_info.sections.\*.name | string | | .text |
action_result.data.\*.attributes.pe_info.sections.\*.raw_size | numeric | | 90112 |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_address | numeric | | 4096 |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_size | numeric | | 90112 |
action_result.data.\*.attributes.pe_info.timestamp | numeric | | 1259933759 |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.count | numeric | | 16 |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.value | string | | virus |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.count | numeric | | 32 |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.value | string | | parite |
action_result.data.\*.attributes.popular_threat_classification.suggested_threat_label | string | | virus.parite/pate |
action_result.data.\*.attributes.reputation | numeric | | 0 |
action_result.data.\*.attributes.sandbox_verdicts.Lastline.\* | string | | xyz |
action_result.data.\*.attributes.sandbox_verdicts.Tencent HABO.\* | string | | xyz |
action_result.data.\*.attributes.sha1 | string | `sha1` | 99999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.attributes.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.attributes.signature_info.\* | string | | xyz |
action_result.data.\*.attributes.size | numeric | | 6285 |
action_result.data.\*.attributes.ssdeep | string | | 192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygi6OLxgUHzYu7ThPBLkv:pq7Mgg0/NdMu/1BLkv |
action_result.data.\*.attributes.tags | string | | python |
action_result.data.\*.attributes.times_submitted | numeric | | 13 |
action_result.data.\*.attributes.tlsh | string | | 9999999999C5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC |
action_result.data.\*.attributes.total_votes.harmless | numeric | | 0 |
action_result.data.\*.attributes.total_votes.malicious | numeric | | 0 |
action_result.data.\*.attributes.trid.\*.file_type | string | | Unix-like shebang (var.1) (gen) |
action_result.data.\*.attributes.trid.\*.probability | numeric | | 100 |
action_result.data.\*.attributes.type_description | string | | Python |
action_result.data.\*.attributes.type_extension | string | | py |
action_result.data.\*.attributes.type_tag | string | | python |
action_result.data.\*.attributes.unique_sources | numeric | | 1 |
action_result.data.\*.attributes.vhash | string | | 999999999904dba990373ab2f3da0c7dd3f |
action_result.data.\*.data.attributes.date | numeric | | 1613651763 |
action_result.data.\*.data.attributes.results.\*.category | string | | undetected |
action_result.data.\*.data.attributes.results.\*.engine_name | string | | CMC |
action_result.data.\*.data.attributes.results.\*.engine_update | string | | 20210218 |
action_result.data.\*.data.attributes.results.\*.engine_version | string | | 2.10.2019.1 |
action_result.data.\*.data.attributes.results.\*.method | string | | blacklist |
action_result.data.\*.data.attributes.results.\*.result | string | | |
action_result.data.\*.data.attributes.results.ALYac.category | string | | undetected |
action_result.data.\*.data.attributes.results.ALYac.engine_name | string | | ALYac |
action_result.data.\*.data.attributes.results.ALYac.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.ALYac.engine_version | string | | 1.1.3.1 |
action_result.data.\*.data.attributes.results.ALYac.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ALYac.result | string | | |
action_result.data.\*.data.attributes.results.APEX.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.APEX.engine_name | string | | APEX |
action_result.data.\*.data.attributes.results.APEX.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.APEX.engine_version | string | | 6.396 |
action_result.data.\*.data.attributes.results.APEX.method | string | | blacklist |
action_result.data.\*.data.attributes.results.APEX.result | string | | |
action_result.data.\*.data.attributes.results.AVG.category | string | | undetected |
action_result.data.\*.data.attributes.results.AVG.engine_name | string | | AVG |
action_result.data.\*.data.attributes.results.AVG.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.AVG.engine_version | string | | 22.11.7701.0 |
action_result.data.\*.data.attributes.results.AVG.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AVG.result | string | | |
action_result.data.\*.data.attributes.results.Acronis.category | string | | undetected |
action_result.data.\*.data.attributes.results.Acronis.engine_name | string | | Acronis |
action_result.data.\*.data.attributes.results.Acronis.engine_update | string | | 20230219 |
action_result.data.\*.data.attributes.results.Acronis.engine_version | string | | 1.2.0.114 |
action_result.data.\*.data.attributes.results.Acronis.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Acronis.result | string | | |
action_result.data.\*.data.attributes.results.AhnLab-V3.category | string | | undetected |
action_result.data.\*.data.attributes.results.AhnLab-V3.engine_name | string | | AhnLab-V3 |
action_result.data.\*.data.attributes.results.AhnLab-V3.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.AhnLab-V3.engine_version | string | | 3.23.1.10344 |
action_result.data.\*.data.attributes.results.AhnLab-V3.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AhnLab-V3.result | string | | |
action_result.data.\*.data.attributes.results.Alibaba.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Alibaba.engine_name | string | | Alibaba |
action_result.data.\*.data.attributes.results.Alibaba.engine_update | string | | 20190527 |
action_result.data.\*.data.attributes.results.Alibaba.engine_version | string | | 0.3.0.5 |
action_result.data.\*.data.attributes.results.Alibaba.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Alibaba.result | string | | |
action_result.data.\*.data.attributes.results.Antiy-AVL.category | string | | undetected |
action_result.data.\*.data.attributes.results.Antiy-AVL.engine_name | string | | Antiy-AVL |
action_result.data.\*.data.attributes.results.Antiy-AVL.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Antiy-AVL.engine_version | string | | 3.0 |
action_result.data.\*.data.attributes.results.Antiy-AVL.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Antiy-AVL.result | string | | |
action_result.data.\*.data.attributes.results.Arcabit.category | string | | undetected |
action_result.data.\*.data.attributes.results.Arcabit.engine_name | string | | Arcabit |
action_result.data.\*.data.attributes.results.Arcabit.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Arcabit.engine_version | string | | 2022.0.0.18 |
action_result.data.\*.data.attributes.results.Arcabit.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Arcabit.result | string | | |
action_result.data.\*.data.attributes.results.Avast-Mobile.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Avast-Mobile.engine_name | string | | Avast-Mobile |
action_result.data.\*.data.attributes.results.Avast-Mobile.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Avast-Mobile.engine_version | string | | 230312-00 |
action_result.data.\*.data.attributes.results.Avast-Mobile.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Avast-Mobile.result | string | | |
action_result.data.\*.data.attributes.results.Avast.category | string | | undetected |
action_result.data.\*.data.attributes.results.Avast.engine_name | string | | Avast |
action_result.data.\*.data.attributes.results.Avast.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Avast.engine_version | string | | 22.11.7701.0 |
action_result.data.\*.data.attributes.results.Avast.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Avast.result | string | | |
action_result.data.\*.data.attributes.results.Avira.category | string | | undetected |
action_result.data.\*.data.attributes.results.Avira.engine_name | string | | Avira |
action_result.data.\*.data.attributes.results.Avira.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Avira.engine_version | string | | 8.3.3.16 |
action_result.data.\*.data.attributes.results.Avira.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Avira.result | string | | |
action_result.data.\*.data.attributes.results.Baidu.category | string | | undetected |
action_result.data.\*.data.attributes.results.Baidu.engine_name | string | | Baidu |
action_result.data.\*.data.attributes.results.Baidu.engine_update | string | | 20190318 |
action_result.data.\*.data.attributes.results.Baidu.engine_version | string | | 1.0.0.2 |
action_result.data.\*.data.attributes.results.Baidu.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Baidu.result | string | | |
action_result.data.\*.data.attributes.results.BitDefender.category | string | | undetected |
action_result.data.\*.data.attributes.results.BitDefender.engine_name | string | | BitDefender |
action_result.data.\*.data.attributes.results.BitDefender.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.BitDefender.engine_version | string | | 7.2 |
action_result.data.\*.data.attributes.results.BitDefender.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BitDefender.result | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_name | string | | BitDefenderFalx |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_update | string | | 20230203 |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_version | string | | 2.0.936 |
action_result.data.\*.data.attributes.results.BitDefenderFalx.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BitDefenderFalx.result | string | | |
action_result.data.\*.data.attributes.results.BitDefenderTheta.category | string | | undetected |
action_result.data.\*.data.attributes.results.BitDefenderTheta.engine_name | string | | BitDefenderTheta |
action_result.data.\*.data.attributes.results.BitDefenderTheta.engine_update | string | | 20230228 |
action_result.data.\*.data.attributes.results.BitDefenderTheta.engine_version | string | | 7.2.37796.0 |
action_result.data.\*.data.attributes.results.BitDefenderTheta.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BitDefenderTheta.result | string | | |
action_result.data.\*.data.attributes.results.Bkav.category | string | | undetected |
action_result.data.\*.data.attributes.results.Bkav.engine_name | string | | Bkav |
action_result.data.\*.data.attributes.results.Bkav.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Bkav.engine_version | string | | 1.3.0.9899 |
action_result.data.\*.data.attributes.results.Bkav.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Bkav.result | string | | |
action_result.data.\*.data.attributes.results.CAT-QuickHeal.category | string | | undetected |
action_result.data.\*.data.attributes.results.CAT-QuickHeal.engine_name | string | | CAT-QuickHeal |
action_result.data.\*.data.attributes.results.CAT-QuickHeal.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.CAT-QuickHeal.engine_version | string | | 22.00 |
action_result.data.\*.data.attributes.results.CAT-QuickHeal.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CAT-QuickHeal.result | string | | |
action_result.data.\*.data.attributes.results.CMC.category | string | | undetected |
action_result.data.\*.data.attributes.results.CMC.engine_name | string | | CMC |
action_result.data.\*.data.attributes.results.CMC.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.CMC.engine_version | string | | 2.4.2022.1 |
action_result.data.\*.data.attributes.results.CMC.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CMC.result | string | | |
action_result.data.\*.data.attributes.results.ClamAV.category | string | | undetected |
action_result.data.\*.data.attributes.results.ClamAV.engine_name | string | | ClamAV |
action_result.data.\*.data.attributes.results.ClamAV.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.ClamAV.engine_version | string | | 1.0.1.0 |
action_result.data.\*.data.attributes.results.ClamAV.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ClamAV.result | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_name | string | | CrowdStrike |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_update | string | | 20220812 |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_version | string | | 1.0 |
action_result.data.\*.data.attributes.results.CrowdStrike.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CrowdStrike.result | string | | |
action_result.data.\*.data.attributes.results.Cylance.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Cylance.engine_name | string | | Cylance |
action_result.data.\*.data.attributes.results.Cylance.engine_update | string | | 20230302 |
action_result.data.\*.data.attributes.results.Cylance.engine_version | string | | 2.0.0.0 |
action_result.data.\*.data.attributes.results.Cylance.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cylance.result | string | | |
action_result.data.\*.data.attributes.results.Cynet.category | string | | undetected |
action_result.data.\*.data.attributes.results.Cynet.engine_name | string | | Cynet |
action_result.data.\*.data.attributes.results.Cynet.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Cynet.engine_version | string | | 4.0.0.27 |
action_result.data.\*.data.attributes.results.Cynet.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cynet.result | string | | |
action_result.data.\*.data.attributes.results.Cyren.category | string | | undetected |
action_result.data.\*.data.attributes.results.Cyren.engine_name | string | | Cyren |
action_result.data.\*.data.attributes.results.Cyren.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Cyren.engine_version | string | | 6.5.1.2 |
action_result.data.\*.data.attributes.results.Cyren.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cyren.result | string | | |
action_result.data.\*.data.attributes.results.DrWeb.category | string | | undetected |
action_result.data.\*.data.attributes.results.DrWeb.engine_name | string | | DrWeb |
action_result.data.\*.data.attributes.results.DrWeb.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.DrWeb.engine_version | string | | 7.0.59.12300 |
action_result.data.\*.data.attributes.results.DrWeb.method | string | | blacklist |
action_result.data.\*.data.attributes.results.DrWeb.result | string | | |
action_result.data.\*.data.attributes.results.ESET-NOD32.category | string | | undetected |
action_result.data.\*.data.attributes.results.ESET-NOD32.engine_name | string | | ESET-NOD32 |
action_result.data.\*.data.attributes.results.ESET-NOD32.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.ESET-NOD32.engine_version | string | | 26892 |
action_result.data.\*.data.attributes.results.ESET-NOD32.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ESET-NOD32.result | string | | |
action_result.data.\*.data.attributes.results.Elastic.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Elastic.engine_name | string | | Elastic |
action_result.data.\*.data.attributes.results.Elastic.engine_update | string | | 20230302 |
action_result.data.\*.data.attributes.results.Elastic.engine_version | string | | 4.0.80 |
action_result.data.\*.data.attributes.results.Elastic.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Elastic.result | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.category | string | | undetected |
action_result.data.\*.data.attributes.results.Emsisoft.engine_name | string | | Emsisoft |
action_result.data.\*.data.attributes.results.Emsisoft.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Emsisoft.engine_version | string | | 2022.6.0.32461 |
action_result.data.\*.data.attributes.results.Emsisoft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Emsisoft.result | string | | |
action_result.data.\*.data.attributes.results.F-Secure.category | string | | undetected |
action_result.data.\*.data.attributes.results.F-Secure.engine_name | string | | F-Secure |
action_result.data.\*.data.attributes.results.F-Secure.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.F-Secure.engine_version | string | | 18.10.1137.128 |
action_result.data.\*.data.attributes.results.F-Secure.method | string | | blacklist |
action_result.data.\*.data.attributes.results.F-Secure.result | string | | |
action_result.data.\*.data.attributes.results.FireEye.category | string | | undetected |
action_result.data.\*.data.attributes.results.FireEye.engine_name | string | | FireEye |
action_result.data.\*.data.attributes.results.FireEye.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.FireEye.engine_version | string | | 35.24.1.0 |
action_result.data.\*.data.attributes.results.FireEye.method | string | | blacklist |
action_result.data.\*.data.attributes.results.FireEye.result | string | | |
action_result.data.\*.data.attributes.results.Fortinet.category | string | | undetected |
action_result.data.\*.data.attributes.results.Fortinet.engine_name | string | | Fortinet |
action_result.data.\*.data.attributes.results.Fortinet.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Fortinet.engine_version | string | | 6.4.258.0 |
action_result.data.\*.data.attributes.results.Fortinet.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Fortinet.result | string | | |
action_result.data.\*.data.attributes.results.GData.category | string | | undetected |
action_result.data.\*.data.attributes.results.GData.engine_name | string | | GData |
action_result.data.\*.data.attributes.results.GData.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.GData.engine_version | string | | A:25.35442B:27.30944 |
action_result.data.\*.data.attributes.results.GData.method | string | | blacklist |
action_result.data.\*.data.attributes.results.GData.result | string | | |
action_result.data.\*.data.attributes.results.Google.category | string | | undetected |
action_result.data.\*.data.attributes.results.Google.engine_name | string | | Google |
action_result.data.\*.data.attributes.results.Google.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Google.engine_version | string | | 1678687243 |
action_result.data.\*.data.attributes.results.Google.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Google.result | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.category | string | | undetected |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_name | string | | Gridinsoft |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_version | string | | 1.0.110.174 |
action_result.data.\*.data.attributes.results.Gridinsoft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Gridinsoft.result | string | | |
action_result.data.\*.data.attributes.results.Ikarus.category | string | | undetected |
action_result.data.\*.data.attributes.results.Ikarus.engine_name | string | | Ikarus |
action_result.data.\*.data.attributes.results.Ikarus.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Ikarus.engine_version | string | | 6.0.33.0 |
action_result.data.\*.data.attributes.results.Ikarus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Ikarus.result | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.category | string | | undetected |
action_result.data.\*.data.attributes.results.Jiangmin.engine_name | string | | Jiangmin |
action_result.data.\*.data.attributes.results.Jiangmin.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Jiangmin.engine_version | string | | 16.0.100 |
action_result.data.\*.data.attributes.results.Jiangmin.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Jiangmin.result | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.category | string | | undetected |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_name | string | | K7AntiVirus |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_version | string | | 12.72.47258 |
action_result.data.\*.data.attributes.results.K7AntiVirus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.K7AntiVirus.result | string | | |
action_result.data.\*.data.attributes.results.K7GW.category | string | | undetected |
action_result.data.\*.data.attributes.results.K7GW.engine_name | string | | K7GW |
action_result.data.\*.data.attributes.results.K7GW.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.K7GW.engine_version | string | | 12.72.47258 |
action_result.data.\*.data.attributes.results.K7GW.method | string | | blacklist |
action_result.data.\*.data.attributes.results.K7GW.result | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.category | string | | undetected |
action_result.data.\*.data.attributes.results.Kaspersky.engine_name | string | | Kaspersky |
action_result.data.\*.data.attributes.results.Kaspersky.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Kaspersky.engine_version | string | | 22.0.1.28 |
action_result.data.\*.data.attributes.results.Kaspersky.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Kaspersky.result | string | | |
action_result.data.\*.data.attributes.results.Lionic.category | string | | undetected |
action_result.data.\*.data.attributes.results.Lionic.engine_name | string | | Lionic |
action_result.data.\*.data.attributes.results.Lionic.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Lionic.engine_version | string | | 7.5 |
action_result.data.\*.data.attributes.results.Lionic.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Lionic.result | string | | |
action_result.data.\*.data.attributes.results.MAX.category | string | | undetected |
action_result.data.\*.data.attributes.results.MAX.engine_name | string | | MAX |
action_result.data.\*.data.attributes.results.MAX.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.MAX.engine_version | string | | 2023.1.4.1 |
action_result.data.\*.data.attributes.results.MAX.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MAX.result | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.category | string | | undetected |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_name | string | | Malwarebytes |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_version | string | | 4.4.4.52 |
action_result.data.\*.data.attributes.results.Malwarebytes.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Malwarebytes.result | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.category | string | | undetected |
action_result.data.\*.data.attributes.results.MaxSecure.engine_name | string | | MaxSecure |
action_result.data.\*.data.attributes.results.MaxSecure.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.MaxSecure.engine_version | string | | 1.0.0.1 |
action_result.data.\*.data.attributes.results.MaxSecure.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MaxSecure.result | string | | |
action_result.data.\*.data.attributes.results.McAfee-GW-Edition.category | string | | undetected |
action_result.data.\*.data.attributes.results.McAfee-GW-Edition.engine_name | string | | McAfee-GW-Edition |
action_result.data.\*.data.attributes.results.McAfee-GW-Edition.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.McAfee-GW-Edition.engine_version | string | | v2021.2.0+4045 |
action_result.data.\*.data.attributes.results.McAfee-GW-Edition.method | string | | blacklist |
action_result.data.\*.data.attributes.results.McAfee-GW-Edition.result | string | | |
action_result.data.\*.data.attributes.results.McAfee.category | string | | undetected |
action_result.data.\*.data.attributes.results.McAfee.engine_name | string | | McAfee |
action_result.data.\*.data.attributes.results.McAfee.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.McAfee.engine_version | string | | 6.0.6.653 |
action_result.data.\*.data.attributes.results.McAfee.method | string | | blacklist |
action_result.data.\*.data.attributes.results.McAfee.result | string | | |
action_result.data.\*.data.attributes.results.MicroWorld-eScan.category | string | | undetected |
action_result.data.\*.data.attributes.results.MicroWorld-eScan.engine_name | string | | MicroWorld-eScan |
action_result.data.\*.data.attributes.results.MicroWorld-eScan.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.MicroWorld-eScan.engine_version | string | | 14.0.409.0 |
action_result.data.\*.data.attributes.results.MicroWorld-eScan.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MicroWorld-eScan.result | string | | |
action_result.data.\*.data.attributes.results.Microsoft.category | string | | undetected |
action_result.data.\*.data.attributes.results.Microsoft.engine_name | string | | Microsoft |
action_result.data.\*.data.attributes.results.Microsoft.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Microsoft.engine_version | string | | 1.1.20000.2 |
action_result.data.\*.data.attributes.results.Microsoft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Microsoft.result | string | | |
action_result.data.\*.data.attributes.results.NANO-Antivirus.category | string | | undetected |
action_result.data.\*.data.attributes.results.NANO-Antivirus.engine_name | string | | NANO-Antivirus |
action_result.data.\*.data.attributes.results.NANO-Antivirus.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.NANO-Antivirus.engine_version | string | | 1.0.146.25743 |
action_result.data.\*.data.attributes.results.NANO-Antivirus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.NANO-Antivirus.result | string | | |
action_result.data.\*.data.attributes.results.Paloalto.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Paloalto.engine_name | string | | Paloalto |
action_result.data.\*.data.attributes.results.Paloalto.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Paloalto.engine_version | string | | 0.9.0.1003 |
action_result.data.\*.data.attributes.results.Paloalto.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Paloalto.result | string | | |
action_result.data.\*.data.attributes.results.Panda.category | string | | undetected |
action_result.data.\*.data.attributes.results.Panda.engine_name | string | | Panda |
action_result.data.\*.data.attributes.results.Panda.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Panda.engine_version | string | | 4.6.4.2 |
action_result.data.\*.data.attributes.results.Panda.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Panda.result | string | | |
action_result.data.\*.data.attributes.results.Rising.category | string | | undetected |
action_result.data.\*.data.attributes.results.Rising.engine_name | string | | Rising |
action_result.data.\*.data.attributes.results.Rising.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Rising.engine_version | string | | 25.0.0.27 |
action_result.data.\*.data.attributes.results.Rising.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Rising.result | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.category | string | | undetected |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_name | string | | SUPERAntiSpyware |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_version | string | | 5.6.0.1032 |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.result | string | | |
action_result.data.\*.data.attributes.results.Sangfor.category | string | | undetected |
action_result.data.\*.data.attributes.results.Sangfor.engine_name | string | | Sangfor |
action_result.data.\*.data.attributes.results.Sangfor.engine_update | string | | 20230309 |
action_result.data.\*.data.attributes.results.Sangfor.engine_version | string | | 2.23.0.0 |
action_result.data.\*.data.attributes.results.Sangfor.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sangfor.result | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.category | string | | undetected |
action_result.data.\*.data.attributes.results.SentinelOne.engine_name | string | | SentinelOne |
action_result.data.\*.data.attributes.results.SentinelOne.engine_update | string | | 20230216 |
action_result.data.\*.data.attributes.results.SentinelOne.engine_version | string | | 23.1.3.2 |
action_result.data.\*.data.attributes.results.SentinelOne.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SentinelOne.result | string | | |
action_result.data.\*.data.attributes.results.Sophos.category | string | | undetected |
action_result.data.\*.data.attributes.results.Sophos.engine_name | string | | Sophos |
action_result.data.\*.data.attributes.results.Sophos.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Sophos.engine_version | string | | 2.1.2.0 |
action_result.data.\*.data.attributes.results.Sophos.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sophos.result | string | | |
action_result.data.\*.data.attributes.results.Symantec.category | string | | undetected |
action_result.data.\*.data.attributes.results.Symantec.engine_name | string | | Symantec |
action_result.data.\*.data.attributes.results.Symantec.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Symantec.engine_version | string | | 1.19.0.0 |
action_result.data.\*.data.attributes.results.Symantec.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Symantec.result | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_name | string | | SymantecMobileInsight |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_update | string | | 20230119 |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_version | string | | 2.0 |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.result | string | | |
action_result.data.\*.data.attributes.results.TACHYON.category | string | | undetected |
action_result.data.\*.data.attributes.results.TACHYON.engine_name | string | | TACHYON |
action_result.data.\*.data.attributes.results.TACHYON.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.TACHYON.engine_version | string | | 2023-03-13.01 |
action_result.data.\*.data.attributes.results.TACHYON.method | string | | blacklist |
action_result.data.\*.data.attributes.results.TACHYON.result | string | | |
action_result.data.\*.data.attributes.results.Tencent.category | string | | undetected |
action_result.data.\*.data.attributes.results.Tencent.engine_name | string | | Tencent |
action_result.data.\*.data.attributes.results.Tencent.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Tencent.engine_version | string | | 1.0.0.1 |
action_result.data.\*.data.attributes.results.Tencent.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Tencent.result | string | | |
action_result.data.\*.data.attributes.results.Trapmine.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Trapmine.engine_name | string | | Trapmine |
action_result.data.\*.data.attributes.results.Trapmine.engine_update | string | | 20230103 |
action_result.data.\*.data.attributes.results.Trapmine.engine_version | string | | 4.0.10.141 |
action_result.data.\*.data.attributes.results.Trapmine.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Trapmine.result | string | | |
action_result.data.\*.data.attributes.results.TrendMicro-HouseCall.category | string | | undetected |
action_result.data.\*.data.attributes.results.TrendMicro-HouseCall.engine_name | string | | TrendMicro-HouseCall |
action_result.data.\*.data.attributes.results.TrendMicro-HouseCall.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.TrendMicro-HouseCall.engine_version | string | | 10.0.0.1040 |
action_result.data.\*.data.attributes.results.TrendMicro-HouseCall.method | string | | blacklist |
action_result.data.\*.data.attributes.results.TrendMicro-HouseCall.result | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.category | string | | undetected |
action_result.data.\*.data.attributes.results.TrendMicro.engine_name | string | | TrendMicro |
action_result.data.\*.data.attributes.results.TrendMicro.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.TrendMicro.engine_version | string | | 11.0.0.1006 |
action_result.data.\*.data.attributes.results.TrendMicro.method | string | | blacklist |
action_result.data.\*.data.attributes.results.TrendMicro.result | string | | |
action_result.data.\*.data.attributes.results.Trustlook.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Trustlook.engine_name | string | | Trustlook |
action_result.data.\*.data.attributes.results.Trustlook.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Trustlook.engine_version | string | | 1.0 |
action_result.data.\*.data.attributes.results.Trustlook.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Trustlook.result | string | | |
action_result.data.\*.data.attributes.results.VBA32.category | string | | undetected |
action_result.data.\*.data.attributes.results.VBA32.engine_name | string | | VBA32 |
action_result.data.\*.data.attributes.results.VBA32.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.VBA32.engine_version | string | | 5.0.0 |
action_result.data.\*.data.attributes.results.VBA32.method | string | | blacklist |
action_result.data.\*.data.attributes.results.VBA32.result | string | | |
action_result.data.\*.data.attributes.results.VIPRE.category | string | | undetected |
action_result.data.\*.data.attributes.results.VIPRE.engine_name | string | | VIPRE |
action_result.data.\*.data.attributes.results.VIPRE.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.VIPRE.engine_version | string | | 6.0.0.35 |
action_result.data.\*.data.attributes.results.VIPRE.method | string | | blacklist |
action_result.data.\*.data.attributes.results.VIPRE.result | string | | |
action_result.data.\*.data.attributes.results.ViRobot.category | string | | undetected |
action_result.data.\*.data.attributes.results.ViRobot.engine_name | string | | ViRobot |
action_result.data.\*.data.attributes.results.ViRobot.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.ViRobot.engine_version | string | | 2014.3.20.0 |
action_result.data.\*.data.attributes.results.ViRobot.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ViRobot.result | string | | |
action_result.data.\*.data.attributes.results.VirIT.category | string | | undetected |
action_result.data.\*.data.attributes.results.VirIT.engine_name | string | | VirIT |
action_result.data.\*.data.attributes.results.VirIT.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.VirIT.engine_version | string | | 9.5.405 |
action_result.data.\*.data.attributes.results.VirIT.method | string | | blacklist |
action_result.data.\*.data.attributes.results.VirIT.result | string | | |
action_result.data.\*.data.attributes.results.Webroot.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.Webroot.engine_name | string | | Webroot |
action_result.data.\*.data.attributes.results.Webroot.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.Webroot.engine_version | string | | 1.0.0.403 |
action_result.data.\*.data.attributes.results.Webroot.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Webroot.result | string | | |
action_result.data.\*.data.attributes.results.Xcitium.category | string | | undetected |
action_result.data.\*.data.attributes.results.Xcitium.engine_name | string | | Xcitium |
action_result.data.\*.data.attributes.results.Xcitium.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.Xcitium.engine_version | string | | 35481 |
action_result.data.\*.data.attributes.results.Xcitium.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Xcitium.result | string | | |
action_result.data.\*.data.attributes.results.Yandex.category | string | | undetected |
action_result.data.\*.data.attributes.results.Yandex.engine_name | string | | Yandex |
action_result.data.\*.data.attributes.results.Yandex.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Yandex.engine_version | string | | 5.5.2.24 |
action_result.data.\*.data.attributes.results.Yandex.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Yandex.result | string | | |
action_result.data.\*.data.attributes.results.Zillya.category | string | | undetected |
action_result.data.\*.data.attributes.results.Zillya.engine_name | string | | Zillya |
action_result.data.\*.data.attributes.results.Zillya.engine_update | string | | 20230310 |
action_result.data.\*.data.attributes.results.Zillya.engine_version | string | | 2.0.0.4829 |
action_result.data.\*.data.attributes.results.Zillya.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Zillya.result | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.category | string | | undetected |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_name | string | | ZoneAlarm |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_version | string | | 1.0 |
action_result.data.\*.data.attributes.results.ZoneAlarm.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ZoneAlarm.result | string | | |
action_result.data.\*.data.attributes.results.Zoner.category | string | | undetected |
action_result.data.\*.data.attributes.results.Zoner.engine_name | string | | Zoner |
action_result.data.\*.data.attributes.results.Zoner.engine_update | string | | 20230312 |
action_result.data.\*.data.attributes.results.Zoner.engine_version | string | | 2.2.2.0 |
action_result.data.\*.data.attributes.results.Zoner.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Zoner.result | string | | |
action_result.data.\*.data.attributes.results.tehtris.category | string | | type-unsupported |
action_result.data.\*.data.attributes.results.tehtris.engine_name | string | | tehtris |
action_result.data.\*.data.attributes.results.tehtris.engine_update | string | | 20230313 |
action_result.data.\*.data.attributes.results.tehtris.engine_version | string | | v0.1.4 |
action_result.data.\*.data.attributes.results.tehtris.method | string | | blacklist |
action_result.data.\*.data.attributes.results.tehtris.result | string | | |
action_result.data.\*.data.attributes.stats.confirmed-timeout | numeric | | 0 |
action_result.data.\*.data.attributes.stats.failure | numeric | | 0 |
action_result.data.\*.data.attributes.stats.harmless | numeric | | 0 |
action_result.data.\*.data.attributes.stats.malicious | numeric | | 0 |
action_result.data.\*.data.attributes.stats.suspicious | numeric | | 0 |
action_result.data.\*.data.attributes.stats.timeout | numeric | | 0 |
action_result.data.\*.data.attributes.stats.type-unsupported | numeric | | 16 |
action_result.data.\*.data.attributes.stats.undetected | numeric | | 59 |
action_result.data.\*.data.attributes.status | string | | completed |
action_result.data.\*.data.id | string | `virustotal scan id` | MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw== |
action_result.data.\*.data.links.item | string | | https://www.virustotal.com/api/v3/files/917c72a2684d1573ea363b2f91e3aedcef1996fc34668ba9d369ad9123d1380f |
action_result.data.\*.data.links.self | string | | https://www.virustotal.com/api/v3/analyses/ZDhhNjY5NmU2NDJlYzUyMDUwMmEwNWE0YWRkOGMxNzk6MTY3ODY4OTQ5Mg== |
action_result.data.\*.data.type | string | | analysis |
action_result.data.\*.id | string | `sha256` | 9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/files/e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.file_info.md5 | string | `md5` | 299999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.meta.file_info.name | string | | update_cr.py |
action_result.data.\*.meta.file_info.sha1 | string | `sha1` | 9999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.meta.file_info.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.file_info.size | numeric | | 6285 |
action_result.data.\*.type | string | | file |
action_result.summary.harmless | numeric | | 0 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.scan_id | string | `virustotal scan id` | u-9999999999c9999ca75016e4c010bc94836366881b021a658ea7f8548b6543c1e |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 59 |
action_result.message | string | | Scan id: 99999999995YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw==, Harmless: 0, Malicious: 0, Suspicious: 0, Undetected: 59 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Get the results using the scan id from a detonate file or detonate url action

Type: **investigate** \
Read only: **True**

For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan_id** | required | Scan ID | string | `virustotal scan id` |
**wait_time** | optional | Number of seconds to wait | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.scan_id | string | `virustotal scan id` | u-9999999999868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 |
action_result.parameter.wait_time | numeric | | 10 |
action_result.data.\*.data.attributes.date | numeric | | 1613467266 |
action_result.data.\*.data.attributes.results.\*.category | string | | harmless |
action_result.data.\*.data.attributes.results.\*.engine_name | string | | CRDF |
action_result.data.\*.data.attributes.results.\*.engine_update | string | | 20210218 |
action_result.data.\*.data.attributes.results.\*.engine_version | string | | 2.10.2019.1 |
action_result.data.\*.data.attributes.results.\*.method | string | | blacklist |
action_result.data.\*.data.attributes.results.\*.result | string | | clean |
action_result.data.\*.data.attributes.results.ADMINUSLabs.category | string | | harmless |
action_result.data.\*.data.attributes.results.ADMINUSLabs.engine_name | string | | ADMINUSLabs |
action_result.data.\*.data.attributes.results.ADMINUSLabs.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ADMINUSLabs.result | string | | clean |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).category | string | | harmless |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).engine_name | string | | AICC (MONITORAPP) |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).method | string | | blacklist |
action_result.data.\*.data.attributes.results.AICC (MONITORAPP).result | string | | clean |
action_result.data.\*.data.attributes.results.AlienVault.category | string | | harmless |
action_result.data.\*.data.attributes.results.AlienVault.engine_name | string | | AlienVault |
action_result.data.\*.data.attributes.results.AlienVault.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AlienVault.result | string | | clean |
action_result.data.\*.data.attributes.results.Antiy-AVL.category | string | | harmless |
action_result.data.\*.data.attributes.results.Antiy-AVL.engine_name | string | | Antiy-AVL |
action_result.data.\*.data.attributes.results.Antiy-AVL.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Antiy-AVL.result | string | | clean |
action_result.data.\*.data.attributes.results.Armis.category | string | | harmless |
action_result.data.\*.data.attributes.results.Armis.engine_name | string | | Armis |
action_result.data.\*.data.attributes.results.Armis.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Armis.result | string | | clean |
action_result.data.\*.data.attributes.results.Artists Against 419.category | string | | harmless |
action_result.data.\*.data.attributes.results.Artists Against 419.engine_name | string | | Artists Against 419 |
action_result.data.\*.data.attributes.results.Artists Against 419.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Artists Against 419.result | string | | clean |
action_result.data.\*.data.attributes.results.AutoShun.category | string | | undetected |
action_result.data.\*.data.attributes.results.AutoShun.engine_name | string | | AutoShun |
action_result.data.\*.data.attributes.results.AutoShun.method | string | | blacklist |
action_result.data.\*.data.attributes.results.AutoShun.result | string | | unrated |
action_result.data.\*.data.attributes.results.Avira.category | string | | harmless |
action_result.data.\*.data.attributes.results.Avira.engine_name | string | | Avira |
action_result.data.\*.data.attributes.results.Avira.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Avira.result | string | | clean |
action_result.data.\*.data.attributes.results.BADWARE.INFO.category | string | | harmless |
action_result.data.\*.data.attributes.results.BADWARE.INFO.engine_name | string | | BADWARE.INFO |
action_result.data.\*.data.attributes.results.BADWARE.INFO.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BADWARE.INFO.result | string | | clean |
action_result.data.\*.data.attributes.results.Baidu-International.category | string | | harmless |
action_result.data.\*.data.attributes.results.Baidu-International.engine_name | string | | Baidu-International |
action_result.data.\*.data.attributes.results.Baidu-International.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Baidu-International.result | string | | clean |
action_result.data.\*.data.attributes.results.BitDefender.category | string | | harmless |
action_result.data.\*.data.attributes.results.BitDefender.engine_name | string | | BitDefender |
action_result.data.\*.data.attributes.results.BitDefender.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BitDefender.result | string | | clean |
action_result.data.\*.data.attributes.results.BlockList.category | string | | harmless |
action_result.data.\*.data.attributes.results.BlockList.engine_name | string | | BlockList |
action_result.data.\*.data.attributes.results.BlockList.method | string | | blacklist |
action_result.data.\*.data.attributes.results.BlockList.result | string | | clean |
action_result.data.\*.data.attributes.results.Blueliv.category | string | | harmless |
action_result.data.\*.data.attributes.results.Blueliv.engine_name | string | | Blueliv |
action_result.data.\*.data.attributes.results.Blueliv.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Blueliv.result | string | | clean |
action_result.data.\*.data.attributes.results.CINS Army.category | string | | harmless |
action_result.data.\*.data.attributes.results.CINS Army.engine_name | string | | CINS Army |
action_result.data.\*.data.attributes.results.CINS Army.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CINS Army.result | string | | clean |
action_result.data.\*.data.attributes.results.CLEAN MX.category | string | | harmless |
action_result.data.\*.data.attributes.results.CLEAN MX.engine_name | string | | CLEAN MX |
action_result.data.\*.data.attributes.results.CLEAN MX.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CLEAN MX.result | string | | clean |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.category | string | | harmless |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.engine_name | string | | CMC Threat Intelligence |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CMC Threat Intelligence.result | string | | clean |
action_result.data.\*.data.attributes.results.CRDF.category | string | | harmless |
action_result.data.\*.data.attributes.results.CRDF.engine_name | string | | CRDF |
action_result.data.\*.data.attributes.results.CRDF.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CRDF.result | string | | clean |
action_result.data.\*.data.attributes.results.Certego.category | string | | harmless |
action_result.data.\*.data.attributes.results.Certego.engine_name | string | | Certego |
action_result.data.\*.data.attributes.results.Certego.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Certego.result | string | | clean |
action_result.data.\*.data.attributes.results.Comodo Valkyrie Verdict.category | string | | undetected |
action_result.data.\*.data.attributes.results.Comodo Valkyrie Verdict.engine_name | string | | Comodo Valkyrie Verdict |
action_result.data.\*.data.attributes.results.Comodo Valkyrie Verdict.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Comodo Valkyrie Verdict.result | string | | unrated |
action_result.data.\*.data.attributes.results.CyRadar.category | string | | harmless |
action_result.data.\*.data.attributes.results.CyRadar.engine_name | string | | CyRadar |
action_result.data.\*.data.attributes.results.CyRadar.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CyRadar.result | string | | clean |
action_result.data.\*.data.attributes.results.Cyan.category | string | | undetected |
action_result.data.\*.data.attributes.results.Cyan.engine_name | string | | Cyan |
action_result.data.\*.data.attributes.results.Cyan.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cyan.result | string | | unrated |
action_result.data.\*.data.attributes.results.CyberCrime.category | string | | harmless |
action_result.data.\*.data.attributes.results.CyberCrime.engine_name | string | | CyberCrime |
action_result.data.\*.data.attributes.results.CyberCrime.method | string | | blacklist |
action_result.data.\*.data.attributes.results.CyberCrime.result | string | | clean |
action_result.data.\*.data.attributes.results.Cyren.category | string | | harmless |
action_result.data.\*.data.attributes.results.Cyren.engine_name | string | | Cyren |
action_result.data.\*.data.attributes.results.Cyren.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Cyren.result | string | | clean |
action_result.data.\*.data.attributes.results.DNS8.category | string | | harmless |
action_result.data.\*.data.attributes.results.DNS8.engine_name | string | | DNS8 |
action_result.data.\*.data.attributes.results.DNS8.method | string | | blacklist |
action_result.data.\*.data.attributes.results.DNS8.result | string | | clean |
action_result.data.\*.data.attributes.results.Dr.Web.category | string | | harmless |
action_result.data.\*.data.attributes.results.Dr.Web.engine_name | string | | Dr.Web |
action_result.data.\*.data.attributes.results.Dr.Web.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Dr.Web.result | string | | clean |
action_result.data.\*.data.attributes.results.ESET.category | string | | harmless |
action_result.data.\*.data.attributes.results.ESET.engine_name | string | | ESET |
action_result.data.\*.data.attributes.results.ESET.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ESET.result | string | | clean |
action_result.data.\*.data.attributes.results.EmergingThreats.category | string | | harmless |
action_result.data.\*.data.attributes.results.EmergingThreats.engine_name | string | | EmergingThreats |
action_result.data.\*.data.attributes.results.EmergingThreats.method | string | | blacklist |
action_result.data.\*.data.attributes.results.EmergingThreats.result | string | | clean |
action_result.data.\*.data.attributes.results.Emsisoft.category | string | | harmless |
action_result.data.\*.data.attributes.results.Emsisoft.engine_name | string | | Emsisoft |
action_result.data.\*.data.attributes.results.Emsisoft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Emsisoft.result | string | | clean |
action_result.data.\*.data.attributes.results.EonScope.category | string | | harmless |
action_result.data.\*.data.attributes.results.EonScope.engine_name | string | | EonScope |
action_result.data.\*.data.attributes.results.EonScope.method | string | | blacklist |
action_result.data.\*.data.attributes.results.EonScope.result | string | | clean |
action_result.data.\*.data.attributes.results.Feodo Tracker.category | string | | harmless |
action_result.data.\*.data.attributes.results.Feodo Tracker.engine_name | string | | Feodo Tracker |
action_result.data.\*.data.attributes.results.Feodo Tracker.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Feodo Tracker.result | string | | clean |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.category | string | | harmless |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.engine_name | string | | Forcepoint ThreatSeeker |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Forcepoint ThreatSeeker.result | string | | clean |
action_result.data.\*.data.attributes.results.Fortinet.category | string | | harmless |
action_result.data.\*.data.attributes.results.Fortinet.engine_name | string | | Fortinet |
action_result.data.\*.data.attributes.results.Fortinet.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Fortinet.result | string | | clean |
action_result.data.\*.data.attributes.results.FraudScore.category | string | | harmless |
action_result.data.\*.data.attributes.results.FraudScore.engine_name | string | | FraudScore |
action_result.data.\*.data.attributes.results.FraudScore.method | string | | blacklist |
action_result.data.\*.data.attributes.results.FraudScore.result | string | | clean |
action_result.data.\*.data.attributes.results.G-Data.category | string | | harmless |
action_result.data.\*.data.attributes.results.G-Data.engine_name | string | | G-Data |
action_result.data.\*.data.attributes.results.G-Data.method | string | | blacklist |
action_result.data.\*.data.attributes.results.G-Data.result | string | | clean |
action_result.data.\*.data.attributes.results.Google Safebrowsing.category | string | | harmless |
action_result.data.\*.data.attributes.results.Google Safebrowsing.engine_name | string | | Google Safebrowsing |
action_result.data.\*.data.attributes.results.Google Safebrowsing.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Google Safebrowsing.result | string | | clean |
action_result.data.\*.data.attributes.results.GreenSnow.category | string | | harmless |
action_result.data.\*.data.attributes.results.GreenSnow.engine_name | string | | GreenSnow |
action_result.data.\*.data.attributes.results.GreenSnow.method | string | | blacklist |
action_result.data.\*.data.attributes.results.GreenSnow.result | string | | clean |
action_result.data.\*.data.attributes.results.Hoplite Industries.category | string | | harmless |
action_result.data.\*.data.attributes.results.Hoplite Industries.engine_name | string | | Hoplite Industries |
action_result.data.\*.data.attributes.results.Hoplite Industries.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Hoplite Industries.result | string | | clean |
action_result.data.\*.data.attributes.results.IPsum.category | string | | harmless |
action_result.data.\*.data.attributes.results.IPsum.engine_name | string | | IPsum |
action_result.data.\*.data.attributes.results.IPsum.method | string | | blacklist |
action_result.data.\*.data.attributes.results.IPsum.result | string | | clean |
action_result.data.\*.data.attributes.results.K7AntiVirus.category | string | | harmless |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_name | string | | K7AntiVirus |
action_result.data.\*.data.attributes.results.K7AntiVirus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.K7AntiVirus.result | string | | clean |
action_result.data.\*.data.attributes.results.Kaspersky.category | string | | harmless |
action_result.data.\*.data.attributes.results.Kaspersky.engine_name | string | | Kaspersky |
action_result.data.\*.data.attributes.results.Kaspersky.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Kaspersky.result | string | | clean |
action_result.data.\*.data.attributes.results.Lionic.category | string | | harmless |
action_result.data.\*.data.attributes.results.Lionic.engine_name | string | | Lionic |
action_result.data.\*.data.attributes.results.Lionic.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Lionic.result | string | | clean |
action_result.data.\*.data.attributes.results.Lumu.category | string | | undetected |
action_result.data.\*.data.attributes.results.Lumu.engine_name | string | | Lumu |
action_result.data.\*.data.attributes.results.Lumu.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Lumu.result | string | | unrated |
action_result.data.\*.data.attributes.results.MalBeacon.category | string | | harmless |
action_result.data.\*.data.attributes.results.MalBeacon.engine_name | string | | MalBeacon |
action_result.data.\*.data.attributes.results.MalBeacon.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MalBeacon.result | string | | clean |
action_result.data.\*.data.attributes.results.MalSilo.category | string | | harmless |
action_result.data.\*.data.attributes.results.MalSilo.engine_name | string | | MalSilo |
action_result.data.\*.data.attributes.results.MalSilo.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MalSilo.result | string | | clean |
action_result.data.\*.data.attributes.results.Malware Domain Blocklist.category | string | | harmless |
action_result.data.\*.data.attributes.results.Malware Domain Blocklist.engine_name | string | | Malware Domain Blocklist |
action_result.data.\*.data.attributes.results.Malware Domain Blocklist.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Malware Domain Blocklist.result | string | | clean |
action_result.data.\*.data.attributes.results.MalwareDomainList.category | string | | harmless |
action_result.data.\*.data.attributes.results.MalwareDomainList.engine_name | string | | MalwareDomainList |
action_result.data.\*.data.attributes.results.MalwareDomainList.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MalwareDomainList.result | string | | clean |
action_result.data.\*.data.attributes.results.MalwarePatrol.category | string | | harmless |
action_result.data.\*.data.attributes.results.MalwarePatrol.engine_name | string | | MalwarePatrol |
action_result.data.\*.data.attributes.results.MalwarePatrol.method | string | | blacklist |
action_result.data.\*.data.attributes.results.MalwarePatrol.result | string | | clean |
action_result.data.\*.data.attributes.results.Malwared.category | string | | harmless |
action_result.data.\*.data.attributes.results.Malwared.engine_name | string | | Malwared |
action_result.data.\*.data.attributes.results.Malwared.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Malwared.result | string | | clean |
action_result.data.\*.data.attributes.results.Netcraft.category | string | | harmless |
action_result.data.\*.data.attributes.results.Netcraft.engine_name | string | | Netcraft |
action_result.data.\*.data.attributes.results.Netcraft.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Netcraft.result | string | | clean |
action_result.data.\*.data.attributes.results.NotMining.category | string | | undetected |
action_result.data.\*.data.attributes.results.NotMining.engine_name | string | | NotMining |
action_result.data.\*.data.attributes.results.NotMining.method | string | | blacklist |
action_result.data.\*.data.attributes.results.NotMining.result | string | | unrated |
action_result.data.\*.data.attributes.results.Nucleon.category | string | | harmless |
action_result.data.\*.data.attributes.results.Nucleon.engine_name | string | | Nucleon |
action_result.data.\*.data.attributes.results.Nucleon.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Nucleon.result | string | | clean |
action_result.data.\*.data.attributes.results.OpenPhish.category | string | | harmless |
action_result.data.\*.data.attributes.results.OpenPhish.engine_name | string | | OpenPhish |
action_result.data.\*.data.attributes.results.OpenPhish.method | string | | blacklist |
action_result.data.\*.data.attributes.results.OpenPhish.result | string | | clean |
action_result.data.\*.data.attributes.results.PREBYTES.category | string | | harmless |
action_result.data.\*.data.attributes.results.PREBYTES.engine_name | string | | PREBYTES |
action_result.data.\*.data.attributes.results.PREBYTES.method | string | | blacklist |
action_result.data.\*.data.attributes.results.PREBYTES.result | string | | clean |
action_result.data.\*.data.attributes.results.PhishLabs.category | string | | undetected |
action_result.data.\*.data.attributes.results.PhishLabs.engine_name | string | | PhishLabs |
action_result.data.\*.data.attributes.results.PhishLabs.method | string | | blacklist |
action_result.data.\*.data.attributes.results.PhishLabs.result | string | | unrated |
action_result.data.\*.data.attributes.results.Phishing Database.category | string | | harmless |
action_result.data.\*.data.attributes.results.Phishing Database.engine_name | string | | Phishing Database |
action_result.data.\*.data.attributes.results.Phishing Database.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Phishing Database.result | string | | clean |
action_result.data.\*.data.attributes.results.Phishtank.category | string | | harmless |
action_result.data.\*.data.attributes.results.Phishtank.engine_name | string | | Phishtank |
action_result.data.\*.data.attributes.results.Phishtank.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Phishtank.result | string | | clean |
action_result.data.\*.data.attributes.results.Quick Heal.category | string | | harmless |
action_result.data.\*.data.attributes.results.Quick Heal.engine_name | string | | Quick Heal |
action_result.data.\*.data.attributes.results.Quick Heal.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Quick Heal.result | string | | clean |
action_result.data.\*.data.attributes.results.Quttera.category | string | | harmless |
action_result.data.\*.data.attributes.results.Quttera.engine_name | string | | Quttera |
action_result.data.\*.data.attributes.results.Quttera.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Quttera.result | string | | clean |
action_result.data.\*.data.attributes.results.Rising.category | string | | harmless |
action_result.data.\*.data.attributes.results.Rising.engine_name | string | | Rising |
action_result.data.\*.data.attributes.results.Rising.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Rising.result | string | | clean |
action_result.data.\*.data.attributes.results.SCUMWARE.org.category | string | | harmless |
action_result.data.\*.data.attributes.results.SCUMWARE.org.engine_name | string | | SCUMWARE.org |
action_result.data.\*.data.attributes.results.SCUMWARE.org.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SCUMWARE.org.result | string | | clean |
action_result.data.\*.data.attributes.results.Sangfor.category | string | | harmless |
action_result.data.\*.data.attributes.results.Sangfor.engine_name | string | | Sangfor |
action_result.data.\*.data.attributes.results.Sangfor.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sangfor.result | string | | clean |
action_result.data.\*.data.attributes.results.SecureBrain.category | string | | harmless |
action_result.data.\*.data.attributes.results.SecureBrain.engine_name | string | | SecureBrain |
action_result.data.\*.data.attributes.results.SecureBrain.method | string | | blacklist |
action_result.data.\*.data.attributes.results.SecureBrain.result | string | | clean |
action_result.data.\*.data.attributes.results.Snort IP sample list.category | string | | harmless |
action_result.data.\*.data.attributes.results.Snort IP sample list.engine_name | string | | Snort IP sample list |
action_result.data.\*.data.attributes.results.Snort IP sample list.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Snort IP sample list.result | string | | clean |
action_result.data.\*.data.attributes.results.Sophos.category | string | | harmless |
action_result.data.\*.data.attributes.results.Sophos.engine_name | string | | Sophos |
action_result.data.\*.data.attributes.results.Sophos.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sophos.result | string | | clean |
action_result.data.\*.data.attributes.results.Spam404.category | string | | harmless |
action_result.data.\*.data.attributes.results.Spam404.engine_name | string | | Spam404 |
action_result.data.\*.data.attributes.results.Spam404.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Spam404.result | string | | clean |
action_result.data.\*.data.attributes.results.Spamhaus.category | string | | harmless |
action_result.data.\*.data.attributes.results.Spamhaus.engine_name | string | | Spamhaus |
action_result.data.\*.data.attributes.results.Spamhaus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Spamhaus.result | string | | clean |
action_result.data.\*.data.attributes.results.StopBadware.category | string | | undetected |
action_result.data.\*.data.attributes.results.StopBadware.engine_name | string | | StopBadware |
action_result.data.\*.data.attributes.results.StopBadware.method | string | | blacklist |
action_result.data.\*.data.attributes.results.StopBadware.result | string | | unrated |
action_result.data.\*.data.attributes.results.StopForumSpam.category | string | | harmless |
action_result.data.\*.data.attributes.results.StopForumSpam.engine_name | string | | StopForumSpam |
action_result.data.\*.data.attributes.results.StopForumSpam.method | string | | blacklist |
action_result.data.\*.data.attributes.results.StopForumSpam.result | string | | clean |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.category | string | | harmless |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.engine_name | string | | Sucuri SiteCheck |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Sucuri SiteCheck.result | string | | clean |
action_result.data.\*.data.attributes.results.Tencent.category | string | | harmless |
action_result.data.\*.data.attributes.results.Tencent.engine_name | string | | Tencent |
action_result.data.\*.data.attributes.results.Tencent.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Tencent.result | string | | clean |
action_result.data.\*.data.attributes.results.ThreatHive.category | string | | harmless |
action_result.data.\*.data.attributes.results.ThreatHive.engine_name | string | | ThreatHive |
action_result.data.\*.data.attributes.results.ThreatHive.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ThreatHive.result | string | | clean |
action_result.data.\*.data.attributes.results.Threatsourcing.category | string | | harmless |
action_result.data.\*.data.attributes.results.Threatsourcing.engine_name | string | | Threatsourcing |
action_result.data.\*.data.attributes.results.Threatsourcing.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Threatsourcing.result | string | | clean |
action_result.data.\*.data.attributes.results.Trustwave.category | string | | harmless |
action_result.data.\*.data.attributes.results.Trustwave.engine_name | string | | Trustwave |
action_result.data.\*.data.attributes.results.Trustwave.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Trustwave.result | string | | clean |
action_result.data.\*.data.attributes.results.URLhaus.category | string | | harmless |
action_result.data.\*.data.attributes.results.URLhaus.engine_name | string | | URLhaus |
action_result.data.\*.data.attributes.results.URLhaus.method | string | | blacklist |
action_result.data.\*.data.attributes.results.URLhaus.result | string | | clean |
action_result.data.\*.data.attributes.results.VX Vault.category | string | | harmless |
action_result.data.\*.data.attributes.results.VX Vault.engine_name | string | | VX Vault |
action_result.data.\*.data.attributes.results.VX Vault.method | string | | blacklist |
action_result.data.\*.data.attributes.results.VX Vault.result | string | | clean |
action_result.data.\*.data.attributes.results.Virusdie External Site Scan.category | string | | harmless |
action_result.data.\*.data.attributes.results.Virusdie External Site Scan.engine_name | string | | Virusdie External Site Scan |
action_result.data.\*.data.attributes.results.Virusdie External Site Scan.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Virusdie External Site Scan.result | string | | clean |
action_result.data.\*.data.attributes.results.Web Security Guard.category | string | | harmless |
action_result.data.\*.data.attributes.results.Web Security Guard.engine_name | string | | Web Security Guard |
action_result.data.\*.data.attributes.results.Web Security Guard.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Web Security Guard.result | string | | clean |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.category | string | | harmless |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.engine_name | string | | Yandex Safebrowsing |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.method | string | | blacklist |
action_result.data.\*.data.attributes.results.Yandex Safebrowsing.result | string | | clean |
action_result.data.\*.data.attributes.results.ZeroCERT.category | string | | harmless |
action_result.data.\*.data.attributes.results.ZeroCERT.engine_name | string | | ZeroCERT |
action_result.data.\*.data.attributes.results.ZeroCERT.method | string | | blacklist |
action_result.data.\*.data.attributes.results.ZeroCERT.result | string | | clean |
action_result.data.\*.data.attributes.results.desenmascara.me.category | string | | harmless |
action_result.data.\*.data.attributes.results.desenmascara.me.engine_name | string | | desenmascara.me |
action_result.data.\*.data.attributes.results.desenmascara.me.method | string | | blacklist |
action_result.data.\*.data.attributes.results.desenmascara.me.result | string | | clean |
action_result.data.\*.data.attributes.results.malwares.com URL checker.category | string | | harmless |
action_result.data.\*.data.attributes.results.malwares.com URL checker.engine_name | string | | malwares.com URL checker |
action_result.data.\*.data.attributes.results.malwares.com URL checker.method | string | | blacklist |
action_result.data.\*.data.attributes.results.malwares.com URL checker.result | string | | clean |
action_result.data.\*.data.attributes.results.securolytics.category | string | | harmless |
action_result.data.\*.data.attributes.results.securolytics.engine_name | string | | securolytics |
action_result.data.\*.data.attributes.results.securolytics.method | string | | blacklist |
action_result.data.\*.data.attributes.results.securolytics.result | string | | clean |
action_result.data.\*.data.attributes.results.zvelo.category | string | | harmless |
action_result.data.\*.data.attributes.results.zvelo.engine_name | string | | zvelo |
action_result.data.\*.data.attributes.results.zvelo.method | string | | blacklist |
action_result.data.\*.data.attributes.results.zvelo.result | string | | clean |
action_result.data.\*.data.attributes.stats.harmless | numeric | | 76 |
action_result.data.\*.data.attributes.stats.malicious | numeric | | 0 |
action_result.data.\*.data.attributes.stats.suspicious | numeric | | 0 |
action_result.data.\*.data.attributes.stats.timeout | numeric | | 0 |
action_result.data.\*.data.attributes.stats.undetected | numeric | | 7 |
action_result.data.\*.data.attributes.status | string | | completed |
action_result.data.\*.data.id | string | | u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 |
action_result.data.\*.data.links.item | string | | https://www.virustotal.com/api/v3/urls/f351f690f46ea50132cc1da00d1f1e2a537bb40f8db5dbf777221981d8d49354 |
action_result.data.\*.data.links.self | string | `url` | https://www.virustotal.com/api/v3/analyses/u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 |
action_result.data.\*.data.type | string | | analysis |
action_result.data.\*.meta.file_info.sha256 | string | | 9999999999149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
action_result.data.\*.meta.url_info.id | string | `sha256` | 19999999999e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488 |
action_result.data.\*.meta.url_info.url | string | | http://shinedezign.tk/ |
action_result.summary.harmless | numeric | | 76 |
action_result.summary.malicious | numeric | | 0 |
action_result.summary.scan_id | string | | u-99999999998f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 |
action_result.summary.suspicious | numeric | | 0 |
action_result.summary.undetected | numeric | | 7 |
action_result.message | string | | Scan id: u-9999999999868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266, Harmless: 76, Malicious: 0, Suspicious: 0, Undetected: 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get cached entries'

Get listing of cached entries

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.date_added | string | | |
action_result.data.\*.date_expires | string | | |
action_result.data.\*.key | string | | |
action_result.data.\*.seconds_left | numeric | | |
action_result.summary.count | numeric | | |
action_result.summary.expiration_interval | numeric | | |
action_result.summary.max_cache_length | numeric | | 1000 |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'clear cache'

Clear all cached entries

Type: **generic** \
Read only: **False**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.status | string | | success |
action_result.data.status | string | | |
action_result.summary.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get quotas'

Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | The username or API key to use to fetch quotas | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.user_id | string | | vt_user |
action_result.data.\*.api_requests_daily.group.allowed | numeric | | 500 |
action_result.data.\*.api_requests_daily.group.inherited_from | string | | vt_group |
action_result.data.\*.api_requests_daily.group.used | numeric | | 2 |
action_result.data.\*.api_requests_daily.user.allowed | numeric | | 500 |
action_result.data.\*.api_requests_daily.user.used | numeric | | 2 |
action_result.data.\*.api_requests_hourly.group.allowed | numeric | | 240 |
action_result.data.\*.api_requests_hourly.group.inherited_from | string | | vt_group |
action_result.data.\*.api_requests_hourly.group.used | numeric | | 0 |
action_result.data.\*.api_requests_hourly.user.allowed | numeric | | 240 |
action_result.data.\*.api_requests_hourly.user.used | numeric | | 0 |
action_result.data.\*.api_requests_monthly.group.allowed | numeric | | 0 |
action_result.data.\*.api_requests_monthly.group.inherited_from | string | | testuser |
action_result.data.\*.api_requests_monthly.group.used | numeric | | 0 |
action_result.data.\*.api_requests_monthly.user.allowed | numeric | | 1000000000 |
action_result.data.\*.api_requests_monthly.user.used | numeric | | 5 |
action_result.data.\*.collections_creation_monthly.user.allowed | numeric | | 20 |
action_result.data.\*.collections_creation_monthly.user.used | numeric | | 0 |
action_result.data.\*.intelligence_downloads_monthly.user.allowed | numeric | | 0 |
action_result.data.\*.intelligence_downloads_monthly.user.used | numeric | | 0 |
action_result.data.\*.intelligence_graphs_private.user.allowed | numeric | | 0 |
action_result.data.\*.intelligence_graphs_private.user.used | numeric | | 0 |
action_result.data.\*.intelligence_hunting_rules.user.allowed | numeric | | 0 |
action_result.data.\*.intelligence_hunting_rules.user.used | numeric | | 0 |
action_result.data.\*.intelligence_retrohunt_jobs_monthly.user.allowed | numeric | | 0 |
action_result.data.\*.intelligence_retrohunt_jobs_monthly.user.used | numeric | | 0 |
action_result.data.\*.intelligence_searches_monthly.user.allowed | numeric | | 0 |
action_result.data.\*.intelligence_searches_monthly.user.used | numeric | | 0 |
action_result.data.\*.intelligence_vtdiff_creation_monthly.user.allowed | numeric | | 0 |
action_result.data.\*.intelligence_vtdiff_creation_monthly.user.used | numeric | | 0 |
action_result.data.\*.monitor_storage_bytes.user.allowed | numeric | | 0 |
action_result.data.\*.monitor_storage_bytes.user.used | numeric | | 0 |
action_result.data.\*.monitor_storage_files.user.allowed | numeric | | 0 |
action_result.data.\*.monitor_storage_files.user.used | numeric | | 0 |
action_result.data.\*.monitor_uploaded_bytes.user.allowed | numeric | | 0 |
action_result.data.\*.monitor_uploaded_bytes.user.used | numeric | | 0 |
action_result.data.\*.monitor_uploaded_files.user.allowed | numeric | | 0 |
action_result.data.\*.monitor_uploaded_files.user.used | numeric | | 0 |
action_result.data.\*.private_scans_monthly.user.allowed | numeric | | 0 |
action_result.data.\*.private_scans_monthly.user.used | numeric | | 0 |
action_result.data.\*.private_scans_per_minute.user.allowed | numeric | | 0 |
action_result.data.\*.private_scans_per_minute.user.used | numeric | | 0 |
action_result.summary.group_daily_api_ratio | numeric | | 0 |
action_result.summary.group_hourly_api_ratio | numeric | | 0 |
action_result.summary.group_monthly_api_ratio | numeric | | 0 |
action_result.summary.user_daily_api_ratio | numeric | | 0 |
action_result.summary.user_hourly_api_ratio | numeric | | 0 |
action_result.summary.user_monthly_api_ratio | numeric | | 0 |
action_result.message | string | | User hourly api ratio: 0, User daily api ratio: 0, User monthly api ratio: 0, |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
