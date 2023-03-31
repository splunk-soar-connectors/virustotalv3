[comment]: # "Auto-generated SOAR connector documentation"
# VirusTotal v3

Publisher: Splunk  
Connector Version: 1.6.0  
Product Vendor: VirusTotal  
Product Name: VirusTotal v3  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

This app integrates with the VirusTotal cloud to implement investigative and reputation actions using v3 APIs

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2021-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the VirusTotal server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |

## Cache Flow

If caching is enabled and whenever you run any reputation action then the output of the action will
be cached in the state file of the asset for which it is run. This cache will have an expiration
time and maximum length, after the expiration time you have set in asset configuration if you run
the get cached entries it will clear the cache.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a VirusTotal v3 asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  required  | password | VirusTotal API key
**poll_interval** |  optional  | numeric | Number of minutes to poll for a detonation result (Default: 5)
**waiting_time** |  optional  | numeric | Number of seconds to wait before polling for a detonation result (Default: 0)
**rate_limit** |  optional  | boolean | Limit number of requests to 4 per minute
**timeout** |  optional  | numeric | Request Timeout (Default: 30 seconds)
**cache_reputation_checks** |  optional  | boolean | Cache virustotal reputation checks
**cache_expiration_interval** |  optional  | numeric | Number of seconds until cached reputation checks expire. Any other value than positive integer will disable caching (Default: 3600 seconds)
**cache_size** |  optional  | numeric | Maximum number of entries in cache. Values of zero or less will not limit size and decimal value will be converted to floor value (Default: 1000)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[domain reputation](#action-domain-reputation) - Queries VirusTotal for domain info  
[file reputation](#action-file-reputation) - Queries VirusTotal for file reputation info  
[get file](#action-get-file) - Downloads a file from VirusTotal and adds it to the vault  
[ip reputation](#action-ip-reputation) - Queries VirusTotal for IP info  
[url reputation](#action-url-reputation) - Queries VirusTotal for URL info (run this action after running detonate url)  
[detonate url](#action-detonate-url) - Load a URL to Virus Total and retrieve analysis results  
[detonate file](#action-detonate-file) - Upload a file to Virus Total and retrieve the analysis results  
[get report](#action-get-report) - Get the results using the scan id from a detonate file or detonate url action  
[get cached entries](#action-get-cached-entries) - Get listing of cached entries  
[clear cache](#action-clear-cache) - Clear all cached entries  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Queries VirusTotal for domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.domain | string |  `domain`  |   test.com 
action_result.data.\*.attributes.categories.BitDefender | string |  |   searchengines 
action_result.data.\*.attributes.categories.Comodo Valkyrie Verdict | string |  |   mobile communications 
action_result.data.\*.attributes.categories.Dr.Web | string |  |   social networks 
action_result.data.\*.attributes.categories.Forcepoint ThreatSeeker | string |  |   search engines and portals 
action_result.data.\*.attributes.categories.Sophos | string |  |   social networks 
action_result.data.\*.attributes.categories.alphaMountain.ai | string |  |   Social Networking 
action_result.data.\*.attributes.categories.sophos | string |  |   search engines 
action_result.data.\*.attributes.creation_date | numeric |  |   874296000 
action_result.data.\*.attributes.jarm | string |  |   27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d 
action_result.data.\*.attributes.last_analysis_results.\*.category | string |  |   harmless 
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string |  |   CRDF 
action_result.data.\*.attributes.last_analysis_results.\*.method | string |  |   blacklist 
action_result.data.\*.attributes.last_analysis_results.\*.result | string |  |   clean 
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string |  |   Symantec 
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric |  |   90 
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric |  |   8 
action_result.data.\*.attributes.last_dns_records.\*.expire | numeric |  |   1800 
action_result.data.\*.attributes.last_dns_records.\*.flag | numeric |  |   0 
action_result.data.\*.attributes.last_dns_records.\*.minimum | numeric |  |   60 
action_result.data.\*.attributes.last_dns_records.\*.priority | numeric |  |   40 
action_result.data.\*.attributes.last_dns_records.\*.refresh | numeric |  |   900 
action_result.data.\*.attributes.last_dns_records.\*.retry | numeric |  |   900 
action_result.data.\*.attributes.last_dns_records.\*.rname | string |  |   dns-admin.test.com 
action_result.data.\*.attributes.last_dns_records.\*.serial | numeric |  |   357917103 
action_result.data.\*.attributes.last_dns_records.\*.tag | string |  |   issue 
action_result.data.\*.attributes.last_dns_records.\*.ttl | numeric |  |   78 
action_result.data.\*.attributes.last_dns_records.\*.type | string |  |   MX 
action_result.data.\*.attributes.last_dns_records.\*.value | string |  `ip`  |   alt3.aspmx.l.test.com 
action_result.data.\*.attributes.last_dns_records_date | numeric |  |   1613638555 
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature | string |  |   811fa6e0af210a512fa773cf16fd62ecae6fdacab57fb71626791b9ad5bfb19841435e7480dba67b1fd17828204f05905379bccc98a7f39a037a5b4eb43f3bb54c51df02137b13abffc343b500319819854920af065afb70a3857657909b0d006de9b7aa2197fe94c2ccde7df14760dd8c5f87d5f89c3b1b835c81f06b727d5ea21fc04c0126ef1377cceb935ccedc969b6b503e5e3c783f0fb13f7dd465d67b807f9d268082449813eb0700e7bd472b238f8c551c07b3e130b88b7fb96799e6d9c1ac8b632603840eeb429e271856a94cd62f1d1bdfeda4f02ae0df7b1d0b80aceab4b73d137f4b4bec851555213fc540dc74defb81761304e3339062d65a60 
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature_algorithm | string |  |   sha256RSA 
action_result.data.\*.attributes.last_https_certificate.extensions.1.3.6.1.4.1.11129.2.4.2 | string |  `sha256`  |   0481f100ef0076007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e 
action_result.data.\*.attributes.last_https_certificate.extensions.CA | boolean |  |   True 
action_result.data.\*.attributes.last_https_certificate.extensions.authority_key_identifier.keyid | string |  `sha1`  |   98d1f86e10ebcf9bec609f18901ba0eb7d09fd2b 
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.CA Issuers | string |  `url`  |   http://pki.goog/gsr2/GTS1O1.crt 
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.OCSP | string |  `url`  |   http://ocsp.pki.goog/gts1o1core 
action_result.data.\*.attributes.last_https_certificate.extensions.certificate_policies | string |  |   1.3.6.1.4.1.11129.2.5.3 
action_result.data.\*.attributes.last_https_certificate.extensions.crl_distribution_points | string |  `url`  |   http://crl.pki.goog/GTS1O1core.crl 
action_result.data.\*.attributes.last_https_certificate.extensions.extended_key_usage | string |  |   serverAuth 
action_result.data.\*.attributes.last_https_certificate.extensions.key_usage | string |  |   ff 
action_result.data.\*.attributes.last_https_certificate.extensions.subject_alternative_name | string |  |   yt.be 
action_result.data.\*.attributes.last_https_certificate.extensions.subject_key_identifier | string |  `sha1`  |   67bf0513cc1c9c4765c43f3fedd687cf88bcd93d 
action_result.data.\*.attributes.last_https_certificate.issuer.C | string |  |   US 
action_result.data.\*.attributes.last_https_certificate.issuer.CN | string |  |   GTS CA 1O1 
action_result.data.\*.attributes.last_https_certificate.issuer.O | string |  |   Test Trust Services 
action_result.data.\*.attributes.last_https_certificate.issuer.OU | string |  |   www.test.com 
action_result.data.\*.attributes.last_https_certificate.public_key.algorithm | string |  |   EC 
action_result.data.\*.attributes.last_https_certificate.public_key.ec.oid | string |  |   secp256r1 
action_result.data.\*.attributes.last_https_certificate.public_key.ec.pub | string |  |   0453d3053c10d8cc8d06a01c02171e8c2d91b355cc188112943a217edc2fe60e3592f329404573e124c077917dcf319f14a6a2c3e433ee695d60a7e9ba3883aa5b 
action_result.data.\*.attributes.last_https_certificate.serial_number | string |  `md5`  |   c4ea98ea7e5e1f430200000000870182 
action_result.data.\*.attributes.last_https_certificate.signature_algorithm | string |  |   sha256RSA 
action_result.data.\*.attributes.last_https_certificate.size | numeric |  |   2441 
action_result.data.\*.attributes.last_https_certificate.subject.C | string |  |   US 
action_result.data.\*.attributes.last_https_certificate.subject.CN | string |  |   \*.test.com 
action_result.data.\*.attributes.last_https_certificate.subject.L | string |  |   Mountain View 
action_result.data.\*.attributes.last_https_certificate.subject.O | string |  |   Test LLC 
action_result.data.\*.attributes.last_https_certificate.subject.ST | string |  |   California 
action_result.data.\*.attributes.last_https_certificate.thumbprint | string |  `sha1`  |   c25b1dc8be5f679087ecd28fb5eae7b3985cf604 
action_result.data.\*.attributes.last_https_certificate.thumbprint_sha256 | string |  `sha256`  |   a29f9d0d85bd02b3150267ac5a820e4aadc9becc7b5884530a549e6d98dac4a3 
action_result.data.\*.attributes.last_https_certificate.validity.not_after | string |  |   2021-04-13 07:57:08 
action_result.data.\*.attributes.last_https_certificate.validity.not_before | string |  |   2021-01-19 07:57:09 
action_result.data.\*.attributes.last_https_certificate.version | string |  |   V3 
action_result.data.\*.attributes.last_https_certificate_date | numeric |  |   1613638555 
action_result.data.\*.attributes.last_modification_date | numeric |  |   1613640948 
action_result.data.\*.attributes.last_update_date | numeric |  |   1568043544 
action_result.data.\*.attributes.popularity_ranks.Alexa.rank | numeric |  |   1 
action_result.data.\*.attributes.popularity_ranks.Alexa.timestamp | numeric |  |   1613576161 
action_result.data.\*.attributes.popularity_ranks.Cisco Umbrella.rank | numeric |  |   1 
action_result.data.\*.attributes.popularity_ranks.Cisco Umbrella.timestamp | numeric |  |   1613489762 
action_result.data.\*.attributes.popularity_ranks.Majestic.rank | numeric |  |   2 
action_result.data.\*.attributes.popularity_ranks.Majestic.timestamp | numeric |  |   1613576163 
action_result.data.\*.attributes.popularity_ranks.Quantcast.rank | numeric |  |   1 
action_result.data.\*.attributes.popularity_ranks.Quantcast.timestamp | numeric |  |   1585755370 
action_result.data.\*.attributes.popularity_ranks.Statvoo.rank | numeric |  |   1 
action_result.data.\*.attributes.popularity_ranks.Statvoo.timestamp | numeric |  |   1613576162 
action_result.data.\*.attributes.registrar | string |  |   MarkMonitor Inc. 
action_result.data.\*.attributes.reputation | numeric |  |   256 
action_result.data.\*.attributes.total_votes.harmless | numeric |  |   104 
action_result.data.\*.attributes.total_votes.malicious | numeric |  |   26 
action_result.data.\*.attributes.whois | string |  |   Creation Date: 1997-09-15T04:00:00Z
DNSSEC: unsigned
Domain Name: TEST.COM
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Name Server: NS1.TEST.COM
Name Server: NS2.TEST.COM
Name Server: NS3.TEST.COM
Name Server: NS4.TEST.COM
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Registrar IANA ID: 292
Registrar URL: http://www.markmonitor.com
Registrar WHOIS Server: whois.markmonitor.com
Registrar: MarkMonitor Inc.
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registry Expiry Date: 2028-09-14T04:00:00Z
Updated Date: 2019-09-09T15:39:04Z 
action_result.data.\*.attributes.whois_date | numeric |  |   1612787278 
action_result.data.\*.id | string |  `domain`  |   test.com 
action_result.data.\*.links.self | string |  `url`  |   https://www.virustotal.com/api/v3/domains/test.com 
action_result.data.\*.type | string |  |   domain 
action_result.summary.harmless | numeric |  |   90 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   8 
action_result.message | string |  |   Harmless: 90, Malicious: 0, Suspicious: 0, Undetected: 8 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'file reputation'
Queries VirusTotal for file reputation info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to query | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  `hash`  `sha256`  `sha1`  `md5`  |   e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.attributes.authentihash | string |  |   ad56160b465f7bd1e7568640397f01fc4f8819ce6f0c1415690ecee646464cec 
action_result.data.\*.attributes.creation_date | numeric |  |   1410950077 
action_result.data.\*.attributes.first_submission_date | numeric |  |   1612961082 
action_result.data.\*.attributes.last_analysis_date | numeric |  |   1613635130 
action_result.data.\*.attributes.last_analysis_results.\*.category | string |  |   undetected 
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string |  |   CMC 
action_result.data.\*.attributes.last_analysis_results.\*.engine_update | string |  |   20210218 
action_result.data.\*.attributes.last_analysis_results.\*.engine_version | string |  |   2.10.2019.1 
action_result.data.\*.attributes.last_analysis_results.\*.method | string |  |   blacklist 
action_result.data.\*.attributes.last_analysis_results.\*.result | string |  |  
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string |  |   Symantec 
action_result.data.\*.attributes.last_analysis_stats.confirmed-timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.failure | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.type-unsupported | numeric |  |   16 
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric |  |   59 
action_result.data.\*.attributes.last_modification_date | numeric |  |   1613635210 
action_result.data.\*.attributes.last_submission_date | numeric |  |   1613635130 
action_result.data.\*.attributes.magic | string |  |   a python2.7\\015script text executable 
action_result.data.\*.attributes.md5 | string |  `md5`  |   2e65153f2c49c91a0206ee7a8c00e659 
action_result.data.\*.attributes.meaningful_name | string |  |   update_cr.py 
action_result.data.\*.attributes.names | string |  |   update_cr.py 
action_result.data.\*.attributes.pe_info.entry_point | numeric |  |   14768 
action_result.data.\*.attributes.pe_info.imphash | string |  |   d7584447a5c5ca9b4a55946317137951 
action_result.data.\*.attributes.pe_info.import_list.\*.library_name | string |  |   COMDLG32.dll 
action_result.data.\*.attributes.pe_info.machine_type | numeric |  |   332 
action_result.data.\*.attributes.pe_info.resource_details.\*.chi2 | numeric |  |   8137.34814453125 
action_result.data.\*.attributes.pe_info.resource_details.\*.entropy | numeric |  |   5.789552211761475 
action_result.data.\*.attributes.pe_info.resource_details.\*.filetype | string |  |   Data 
action_result.data.\*.attributes.pe_info.resource_details.\*.lang | string |  |   ENGLISH US 
action_result.data.\*.attributes.pe_info.resource_details.\*.sha256 | string |  |   c37bc8f6dbf81e8d88978836b23ee932ade6652ba798989bf20697afffd6113e 
action_result.data.\*.attributes.pe_info.resource_details.\*.type | string |  |   RT_BITMAP 
action_result.data.\*.attributes.pe_info.resource_langs.ENGLISH US | numeric |  |   6 
action_result.data.\*.attributes.pe_info.resource_langs.RUSSIAN | numeric |  |   1 
action_result.data.\*.attributes.pe_info.resource_types.RT_BITMAP | numeric |  |   2 
action_result.data.\*.attributes.pe_info.resource_types.RT_DIALOG | numeric |  |   2 
action_result.data.\*.attributes.pe_info.resource_types.RT_MANIFEST | numeric |  |   1 
action_result.data.\*.attributes.pe_info.resource_types.RT_MENU | numeric |  |   1 
action_result.data.\*.attributes.pe_info.resource_types.RT_VERSION | numeric |  |   1 
action_result.data.\*.attributes.pe_info.rich_pe_header_hash | string |  |   fa4dbca9180170710b3c245464efa483 
action_result.data.\*.attributes.pe_info.sections.\*.chi2 | numeric |  |   292981.44 
action_result.data.\*.attributes.pe_info.sections.\*.entropy | numeric |  |   6.75 
action_result.data.\*.attributes.pe_info.sections.\*.flags | string |  |   rx 
action_result.data.\*.attributes.pe_info.sections.\*.md5 | string |  |   a13f88c3e0636712e10326c07d56b645 
action_result.data.\*.attributes.pe_info.sections.\*.name | string |  |   .text 
action_result.data.\*.attributes.pe_info.sections.\*.raw_size | numeric |  |   54784 
action_result.data.\*.attributes.pe_info.sections.\*.virtual_address | numeric |  |   4096 
action_result.data.\*.attributes.pe_info.sections.\*.virtual_size | numeric |  |   54434 
action_result.data.\*.attributes.pe_info.timestamp | numeric |  |   1410950077 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.count | numeric |  |   30 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.value | string |  |   trojan 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.count | numeric |  |   13 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.value | string |  |   zbot 
action_result.data.\*.attributes.popular_threat_classification.suggested_threat_label | string |  |   trojan.zbot/foreign 
action_result.data.\*.attributes.reputation | numeric |  |   0 
action_result.data.\*.attributes.sandbox_verdicts.Tencent HABO.\* | string |  |   xyz 
action_result.data.\*.attributes.sha1 | string |  `sha1`  |   6802169a19142292710254cde97df84e46dfe33a 
action_result.data.\*.attributes.sha256 | string |  `sha256`  |   e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.attributes.signature_info.\* | string |  |   xyz 
action_result.data.\*.attributes.size | numeric |  |   6285 
action_result.data.\*.attributes.ssdeep | string |  |   192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygi6OLxgUHzYu7ThPBLkv:pq7Mgg0/NdMu/1BLkv 
action_result.data.\*.attributes.tags | string |  |   python 
action_result.data.\*.attributes.times_submitted | numeric |  |   13 
action_result.data.\*.attributes.tlsh | string |  |   T1F7D10E05AC5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC 
action_result.data.\*.attributes.total_votes.harmless | numeric |  |   0 
action_result.data.\*.attributes.total_votes.malicious | numeric |  |   0 
action_result.data.\*.attributes.trid.\*.file_type | string |  |   Unix-like shebang (var.1) (gen) 
action_result.data.\*.attributes.trid.\*.probability | numeric |  |   100 
action_result.data.\*.attributes.type_description | string |  |   Python 
action_result.data.\*.attributes.type_extension | string |  |   py 
action_result.data.\*.attributes.type_tag | string |  |   python 
action_result.data.\*.attributes.unique_sources | numeric |  |   1 
action_result.data.\*.attributes.vhash | string |  |   025056657d755510804011z9005b9z25z12z3afz 
action_result.data.\*.id | string |  `sha256`  |   e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.links.self | string |  `url`  |   https://www.virustotal.com/api/v3/files/e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.type | string |  |   file 
action_result.summary.harmless | numeric |  |   0 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   59 
action_result.message | string |  |   Harmless: 0, Malicious: 0, Suspicious: 0, Undetected: 59 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get file'
Downloads a file from VirusTotal and adds it to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file to get | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  `hash`  `sha256`  `sha1`  `md5`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'ip reputation'
Queries VirusTotal for IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   2.3.4.5 
action_result.data.\*.attributes.as_owner | string |  |   Orange 
action_result.data.\*.attributes.asn | numeric |  |   3215 
action_result.data.\*.attributes.continent | string |  |   EU 
action_result.data.\*.attributes.country | string |  |   FR 
action_result.data.\*.attributes.crowdsourced_context.\*.detail | string |  |   A domain seen in a CnC panel URL for the Oski malware resolved to this IP address 
action_result.data.\*.attributes.crowdsourced_context.\*.severity | string |  |   high 
action_result.data.\*.attributes.crowdsourced_context.\*.source | string |  |   benkow.cc 
action_result.data.\*.attributes.crowdsourced_context.\*.timestamp | numeric |  |   1622592000 
action_result.data.\*.attributes.crowdsourced_context.\*.title | string |  |   CnC Panel 
action_result.data.\*.attributes.jarm | string |  |   29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae 
action_result.data.\*.attributes.last_analysis_results.\*.category | string |  |   harmless 
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string |  |   CRDF 
action_result.data.\*.attributes.last_analysis_results.\*.method | string |  |   blacklist 
action_result.data.\*.attributes.last_analysis_results.\*.result | string |  |   clean 
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string |  |   Symantec 
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric |  |   86 
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric |  |   11 
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature | string |  |   a60f993e5b931eed2a66b7aef3c70912cd032acbd2c8791021a3c8cb90b38c579d5fa02d04e4e897b1762981b455d77cea92c56bcf902451a76148582a1e80acc1aeb2a0d72f7e8db8739f874e83a48553311eb3cfe48a0d065a309cedf35930ae3e2cb0d4dca8dba64dc7b5f707debac4f28ce313db8623e235790002b37a8dbc63c99276335c4a59faf1957d5384fc318c56b159e51213c21699e328821f64efc433d74372962d6d160f92b5f1dbbc4e8e11c74ce673e8c52f6270c40c1192cf7bf2bbf44660818b8999085388ac8949332f178b294d409334e8d70ca051a5a7ed53df82e58a46ee2c07afa08f0e0f9ea87311f1a8e79ad3406292e811a5c6 
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature_algorithm | string |  |   sha256RSA 
action_result.data.\*.attributes.last_https_certificate.extensions.1.3.6.1.4.1.11129.2.4.2 | string |  |   0481f100ef007600eec095ee8d72640f92e3c3b91bc712a3696a097b4b6a1a14 
action_result.data.\*.attributes.last_https_certificate.extensions.CA | boolean |  |   True 
action_result.data.\*.attributes.last_https_certificate.extensions.authority_key_identifier.keyid | string |  |   8a747faf85cdee95cd3d9cd0e24614f371351d27 
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.CA Issuers | string |  |   http://pki.goog/repo/certs/gts1c3.der 
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.OCSP | string |  |   http://ocsp.pki.goog/gts1c3 
action_result.data.\*.attributes.last_https_certificate.extensions.subject_key_identifier | string |  |   a8de321f3772284cf53c30f681f14bf6ed035cd9 
action_result.data.\*.attributes.last_https_certificate.issuer.\* | string |  |   xyz 
action_result.data.\*.attributes.last_https_certificate.public_key.algorithm | string |  |   RSA 
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.exponent | string |  |   010001 
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.key_size | numeric |  |   2048 
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.modulus | string |  |   00befdaf74bea72e3cb68a2a6bb74521f2ee951338a5d9f6a738f98996e2d72295009f544112aa918e99b93ab48f073322711b992887a46211dc853c48e2f22372419c8841221f3dad453289c2331d3b4c881c67660ecc5093bf601130a7aef9f54419ee8e64754c3b07125893af7dabf0bb0f7232d0226605620e12a4416fb22d5c9182394941b218009f6fe2d28d170a1042a0aa726eb9b052a84a57597a4b9a556be00c004ba024bd310d9e4faf17482b137f81b35f470ead7d7d9e418a6653799e9d04f9fd1d4b588809c0e2ac0680f406ba8f4358a143e3cacc7fe792ab9655cc73729dbcd3d7362a7ffe6f903942dc3d588c97917930a9b28b8561c9219b 
action_result.data.\*.attributes.last_https_certificate.serial_number | string |  |   25c739f93320b7b0a00000000f2c8e9 
action_result.data.\*.attributes.last_https_certificate.signature_algorithm | string |  |   sha256RSA 
action_result.data.\*.attributes.last_https_certificate.size | numeric |  |   1509 
action_result.data.\*.attributes.last_https_certificate.subject.CN | string |  |   dns.test 
action_result.data.\*.attributes.last_https_certificate.thumbprint | string |  |   3336113948b043f8f258cceebe9eb7a8dd7d06de 
action_result.data.\*.attributes.last_https_certificate.thumbprint_sha256 | string |  |   5349f6e0344c78df40dfcfc2ecd6f83d01b4bcf1def8c548c87691211d904f05 
action_result.data.\*.attributes.last_https_certificate.validity.not_after | string |  |   2021-10-04 03:52:55 
action_result.data.\*.attributes.last_https_certificate.validity.not_before | string |  |   2021-07-12 03:52:56 
action_result.data.\*.attributes.last_https_certificate.version | string |  |   V3 
action_result.data.\*.attributes.last_https_certificate_date | numeric |  |   1628548284 
action_result.data.\*.attributes.last_modification_date | numeric |  |   1612735030 
action_result.data.\*.attributes.network | string |  |   2.0.0.0/12 
action_result.data.\*.attributes.regional_internet_registry | string |  |   RIPE NCC 
action_result.data.\*.attributes.reputation | numeric |  |   0 
action_result.data.\*.attributes.total_votes.harmless | numeric |  |   0 
action_result.data.\*.attributes.total_votes.malicious | numeric |  |   0 
action_result.data.\*.attributes.whois | string |  |   NetRange: 2.0.0.0 - 2.255.255.255
CIDR: 2.0.0.0/8
NetName: 2-RIPE
NetHandle: NET-2-0-0-0-1
Parent: ()
NetType: Allocated to RIPE NCC
OriginAS: 
Organization: RIPE Network Coordination Centre (RIPE)
RegDate: 2009-09-29
Updated: 2009-09-30
Comment: These addresses have been further assigned to users in
Comment: the RIPE NCC region. Contact information can be found in
Comment: the RIPE database at http://www.ripe.net/whois
Ref: https://rdap.arin.net/registry/ip/2.0.0.0
ResourceLink: https://apps.db.ripe.net/search/query.html
ResourceLink: whois.ripe.net
OrgName: RIPE Network Coordination Centre
OrgId: RIPE
Address: P.O. Box 10096
City: Amsterdam
StateProv: 
PostalCode: 1001EB
Country: NL
RegDate: 
Updated: 2013-07-29
Ref: https://rdap.arin.net/registry/entity/RIPE
ReferralServer: whois://whois.ripe.net
ResourceLink: https://apps.db.ripe.net/search/query.html
OrgAbuseHandle: ABUSE3850-ARIN
OrgAbuseName: Abuse Contact
OrgAbusePhone: +31205354444 
OrgAbuseEmail: abuse@ripe.net
OrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE3850-ARIN
OrgTechHandle: RNO29-ARIN
OrgTechName: RIPE NCC Operations
OrgTechPhone: +31 20 535 4444 
OrgTechEmail: hostmaster@ripe.net
OrgTechRef: https://rdap.arin.net/registry/entity/RNO29-ARIN
inetnum: 2.3.0.0 - 2.3.7.255
netname: IP2000-ADSL-BAS
descr: POP CLE
country: FR
admin-c: WITR1-RIPE
tech-c: WITR1-RIPE
status: ASSIGNED PA
remarks: for hacking, spamming or security problems send mail to
remarks: abuse@orange.fr
mnt-by: FT-BRX
created: 2017-07-27T08:58:11Z
last-modified: 2017-07-27T08:58:11Z
source: RIPE
role: Wanadoo France Technical Role
address: FRANCE TELECOM/SCR
address: 48 rue Camille Desmoulins
address: 92791 ISSY LES MOULINEAUX CEDEX 9
address: FR
phone: +33 1 58 88 50 00
abuse-mailbox: abuse@orange.fr
admin-c: BRX1-RIPE
tech-c: BRX1-RIPE
nic-hdl: WITR1-RIPE
mnt-by: FT-BRX
created: 2001-12-04T17:57:08Z
last-modified: 2013-07-16T14:09:50Z
source: RIPE # Filtered
route: 2.3.0.0/16
descr: France Telecom Orange
origin: AS3215
mnt-by: RAIN-TRANSPAC
mnt-by: FT-BRX
created: 2012-11-22T09:32:05Z
last-modified: 2012-11-22T09:32:05Z
source: RIPE
 
action_result.data.\*.attributes.whois_date | numeric |  |   1612735030 
action_result.data.\*.id | string |  `ip`  |   2.3.4.5 
action_result.data.\*.links.self | string |  `url`  |   https://www.virustotal.com/api/v3/ip_addresses/2.3.4.5 
action_result.data.\*.type | string |  |   ip_address 
action_result.summary.harmless | numeric |  |   86 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   11 
action_result.message | string |  |   Harmless: 86, Malicious: 0, Suspicious: 0, Undetected: 11 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'url reputation'
Queries VirusTotal for URL info (run this action after running detonate url)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `domain`  |   http://www.test123.com 
action_result.data.\*.attributes.categories.\* | string |  |   searchengines 
action_result.data.\*.attributes.categories.Dr.Web | string |  |   e-mail 
action_result.data.\*.attributes.categories.alphaMountain.ai | string |  |   File Sharing/Storage, Search Engines/Portals 
action_result.data.\*.attributes.first_submission_date | numeric |  |   1618399455 
action_result.data.\*.attributes.last_analysis_date | numeric |  |   1618399455 
action_result.data.\*.attributes.last_analysis_results.\*.category | string |  |   harmless 
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string |  |   CRDF 
action_result.data.\*.attributes.last_analysis_results.\*.method | string |  |   blacklist 
action_result.data.\*.attributes.last_analysis_results.\*.result | string |  |   clean 
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string |  |   Symantec 
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric |  |   78 
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric |  |   1 
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric |  |   8 
action_result.data.\*.attributes.last_final_url | string |  |   https://www.test.com 
action_result.data.\*.attributes.last_http_response_code | numeric |  |   200 
action_result.data.\*.attributes.last_http_response_content_length | numeric |  |   154896 
action_result.data.\*.attributes.last_http_response_content_sha256 | string |  |   e84603534b9c77669d1ebc821aed90fb34e31b587a4df32eba708193b25770d9 
action_result.data.\*.attributes.last_http_response_cookies.\* | string |  |   xyz 
action_result.data.\*.attributes.last_http_response_headers.\* | string |  |   same-origin-allow-popups; report-to="TestUi" 
action_result.data.\*.attributes.last_modification_date | numeric |  |   1618399456 
action_result.data.\*.attributes.last_submission_date | numeric |  |   1618399455 
action_result.data.\*.attributes.reputation | numeric |  |   0 
action_result.data.\*.attributes.times_submitted | numeric |  |   1 
action_result.data.\*.attributes.title | string |  |   Test 
action_result.data.\*.attributes.total_votes.harmless | numeric |  |   0 
action_result.data.\*.attributes.total_votes.malicious | numeric |  |   0 
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.id | string |  |   7241469 
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.timestamp | numeric |  |   1627544121 
action_result.data.\*.attributes.trackers.ScoreCard Research Beacon.\*.url | string |  |   https://sb.scorecardresearch.com/p?c1=2&c2=7241469&c7=https%3A%2F%2Fin.yahoo.com%2F&c5=97684142&cv=2.0&cj=1&c14=-1 
action_result.data.\*.attributes.trackers.Yahoo Dot Tags.\*.timestamp | numeric |  |   1627544121 
action_result.data.\*.attributes.trackers.Yahoo Dot Tags.\*.url | string |  |   https://s.yimg.com/rq/darla/4-6-0/js/g-r-min.js 
action_result.data.\*.attributes.url | string |  |   https://www.test.com 
action_result.data.\*.id | string |  |   e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 
action_result.data.\*.links.self | string |  |   https://www.virustotal.com/api/v3/urls/e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 
action_result.data.\*.type | string |  |   url 
action_result.summary.harmless | numeric |  |   80 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.scan_id | string |  `virustotal scan id`  |   9 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   9 
action_result.message | string |  |   Scan id: u-8d63a6cc87718dd52151f0e6fea2ff6fbf12d68a11046ba4ea3258546906c74f-1613644669, Harmless: 74, Malicious: 0, Suspicious: 0, Undetected: 9 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'detonate url'
Load a URL to Virus Total and retrieve analysis results

Type: **investigate**  
Read only: **True**

<b>detonate url</b> will send a URL to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given URL has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url`  `domain` 
**wait_time** |  optional  | Number of seconds to wait | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `domain`  |   https://www.123test.com 
action_result.parameter.wait_time | numeric |  |   10 
action_result.data.\*.attributes.categories.\* | string |  |   searchengines 
action_result.data.\*.attributes.categories.Dr.Web | string |  |   e-mail 
action_result.data.\*.attributes.first_submission_date | numeric |  |   1618399455 
action_result.data.\*.attributes.last_analysis_date | numeric |  |   1618399455 
action_result.data.\*.attributes.last_analysis_results.\*.category | string |  |   harmless 
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string |  |   CRDF 
action_result.data.\*.attributes.last_analysis_results.\*.method | string |  |   blacklist 
action_result.data.\*.attributes.last_analysis_results.\*.result | string |  |   clean 
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string |  |   Symantec 
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric |  |   78 
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric |  |   1 
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric |  |   8 
action_result.data.\*.attributes.last_final_url | string |  |   https://www.test.com 
action_result.data.\*.attributes.last_http_response_code | numeric |  |   200 
action_result.data.\*.attributes.last_http_response_content_length | numeric |  |   154896 
action_result.data.\*.attributes.last_http_response_content_sha256 | string |  |   e84603534b9c77669d1ebc821aed90fb34e31b587a4df32eba708193b25770d9 
action_result.data.\*.attributes.last_http_response_cookies.\* | string |  |   xyz 
action_result.data.\*.attributes.last_http_response_headers.\* | string |  |   same-origin-allow-popups; report-to="TestUi" 
action_result.data.\*.attributes.last_modification_date | numeric |  |   1618399456 
action_result.data.\*.attributes.last_submission_date | numeric |  |   1618399455 
action_result.data.\*.attributes.reputation | numeric |  |   0 
action_result.data.\*.attributes.times_submitted | numeric |  |   1 
action_result.data.\*.attributes.title | string |  |   Test 
action_result.data.\*.attributes.total_votes.harmless | numeric |  |   0 
action_result.data.\*.attributes.total_votes.malicious | numeric |  |   0 
action_result.data.\*.attributes.url | string |  |   https://www.test.com 
action_result.data.\*.data.attributes.date | numeric |  |   1613648861 
action_result.data.\*.data.attributes.results.\*.category | string |  |   harmless 
action_result.data.\*.data.attributes.results.\*.engine_name | string |  |   CRDF 
action_result.data.\*.data.attributes.results.\*.method | string |  |   blacklist 
action_result.data.\*.data.attributes.results.\*.result | string |  |   clean 
action_result.data.\*.data.attributes.stats.harmless | numeric |  |   76 
action_result.data.\*.data.attributes.stats.malicious | numeric |  |   0 
action_result.data.\*.data.attributes.stats.suspicious | numeric |  |   0 
action_result.data.\*.data.attributes.stats.timeout | numeric |  |   0 
action_result.data.\*.data.attributes.stats.undetected | numeric |  |   7 
action_result.data.\*.data.attributes.status | string |  |   completed 
action_result.data.\*.data.id | string |  `virustotal scan id`  |   u-e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761-1613648861 
action_result.data.\*.data.type | string |  |   analysis 
action_result.data.\*.id | string |  |   e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 
action_result.data.\*.links.self | string |  |   https://www.virustotal.com/api/v3/urls/e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 
action_result.data.\*.meta.url_info.id | string |  `sha256`  |   e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761 
action_result.data.\*.meta.url_info.url | string |  `url`  |   https://www.123test.com/ 
action_result.data.\*.type | string |  |   url 
action_result.summary.harmless | numeric |  |   80 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.scan_id | string |  `virustotal scan id`  |   9 
action_result.summary.scan_id | string |  |   u-e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761-1613648861 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   7 
action_result.message | string |  |   Scan id: u-e4195c91df67204cf910c8472bdb0a676eb054785b285364f9e23a6caca06761-1613648861, Harmless: 76, Malicious: 0, Suspicious: 0, Undetected: 7 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'detonate file'
Upload a file to Virus Total and retrieve the analysis results

Type: **investigate**  
Read only: **True**

<b>detonate file</b> will send a file to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results.<br/>Wait time parameter will be considered only if the given file has not been previously submitted to the VirusTotal Server. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** |  required  | The Vault ID of the file to scan | string |  `vault id`  `sha1` 
**wait_time** |  optional  | Number of seconds to wait | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.vault_id | string |  `vault id`  `sha1`  |   6802169a19142292710254cde97df84e46dfe33a 
action_result.parameter.wait_time | numeric |  |   10 
action_result.data.\*.attributes.androguard.AndroguardVersion | string |  |   3.0-dev 
action_result.data.\*.attributes.androguard.AndroidApplication | numeric |  |   1 
action_result.data.\*.attributes.androguard.AndroidApplicationError | boolean |  |   False 
action_result.data.\*.attributes.androguard.AndroidApplicationInfo | string |  |   APK 
action_result.data.\*.attributes.androguard.AndroidVersionCode | string |  |   1 
action_result.data.\*.attributes.androguard.AndroidVersionName | string |  |   1.0 
action_result.data.\*.attributes.androguard.MinSdkVersion | string |  |   11 
action_result.data.\*.attributes.androguard.Package | string |  |   com.ibm.android.analyzer.test 
action_result.data.\*.attributes.androguard.RiskIndicator.APK.\* | numeric |  |   1 
action_result.data.\*.attributes.androguard.RiskIndicator.PERM.\* | numeric |  |   1 
action_result.data.\*.attributes.androguard.TargetSdkVersion | string |  |   11 
action_result.data.\*.attributes.androguard.VTAndroidInfo | numeric |  |   1.41 
action_result.data.\*.attributes.androguard.certificate.Issuer.\* | string |  |   C:US, CN:Android Debug, O:Android 
action_result.data.\*.attributes.androguard.certificate.Subject.\* | string |  |   US 
action_result.data.\*.attributes.androguard.certificate.serialnumber | string |  |   6f20b2e6 
action_result.data.\*.attributes.androguard.certificate.thumbprint | string |  |   7bd81368b868225bde96fc1a3fee59a8ea06296a 
action_result.data.\*.attributes.androguard.certificate.validfrom | string |  |   2016-01-27 08:46:16 
action_result.data.\*.attributes.androguard.certificate.validto | string |  |   2046-01-19 08:46:16 
action_result.data.\*.attributes.androguard.main_activity | string |  |   com.ibm.android.analyzer.test.xas.CAS 
action_result.data.\*.attributes.androguard.permission_details.android.permission.\*.full_description | string |  |   Allows an application to create network sockets. 
action_result.data.\*.attributes.androguard.permission_details.android.permission.\*.permission_type | string |  |   dangerous 
action_result.data.\*.attributes.androguard.permission_details.android.permission.\*.short_description | string |  |   full Internet access 
action_result.data.\*.attributes.androguard.permission_details.com.ibm.android.analyzer.test.\*.full_description | string |  |   Unknown permission from android reference 
action_result.data.\*.attributes.androguard.permission_details.com.ibm.android.analyzer.test.\*.permission_type | string |  |   normal 
action_result.data.\*.attributes.androguard.permission_details.com.ibm.android.analyzer.test.\*.short_description | string |  |   Unknown permission from android reference 
action_result.data.\*.attributes.authentihash | string |  |   49a3f06ecca601c12ac88d70736e5a5064dac716fe071ce9e3bb206d67b1b9a5 
action_result.data.\*.attributes.bundle_info.extensions.\* | numeric |  |   1 
action_result.data.\*.attributes.bundle_info.file_types.\* | numeric |  |   1 
action_result.data.\*.attributes.bundle_info.highest_datetime | string |  |   2019-01-03 12:33:40 
action_result.data.\*.attributes.bundle_info.lowest_datetime | string |  |   2019-01-03 12:33:40 
action_result.data.\*.attributes.bundle_info.num_children | numeric |  |   1 
action_result.data.\*.attributes.bundle_info.type | string |  |   ZIP 
action_result.data.\*.attributes.bundle_info.uncompressed_size | numeric |  |   481 
action_result.data.\*.attributes.bytehero_info | string |  |   Trojan.Win32.Heur.Gen 
action_result.data.\*.attributes.creation_date | numeric |  |   1539102614 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.alert_severity | string |  |   medium 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_category | string |  |   Potentially Bad Traffic 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_id | string |  |   1:2027865 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_msg | string |  |   ET INFO Observed DNS Query to .cloud TLD 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_raw | string |  |   alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns.query; content:".cloud"; nocase; endswith; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027865; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2019_08_13, deployment Perimeter, former_category INFO, signature_severity Major, updated_at 2020_09_17;) 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_source | string |  |   Proofpoint Emerging Threats Open 
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_url | string |  |   https://rules.emergingthreats.net/ 
action_result.data.\*.attributes.crowdsourced_ids_stats.\* | numeric |  |   0 
action_result.data.\*.attributes.first_seen_itw_date | numeric |  |   1502111702 
action_result.data.\*.attributes.first_submission_date | numeric |  |   1612961082 
action_result.data.\*.attributes.html_info.iframes.\*.attributes.\* | string |  |   ./test_html_files/list.html 
action_result.data.\*.attributes.html_info.scripts.\*.attributes.src | string |  |   ./test_html_files/exerc.js.download 
action_result.data.\*.attributes.last_analysis_date | numeric |  |   1613635130 
action_result.data.\*.attributes.last_analysis_results.\*.category | string |  |   undetected 
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string |  |   CMC 
action_result.data.\*.attributes.last_analysis_results.\*.engine_update | string |  |   20210218 
action_result.data.\*.attributes.last_analysis_results.\*.engine_version | string |  |   2.10.2019.1 
action_result.data.\*.attributes.last_analysis_results.\*.method | string |  |   blacklist 
action_result.data.\*.attributes.last_analysis_results.\*.result | string |  |  
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string |  |   Symantec 
action_result.data.\*.attributes.last_analysis_stats.confirmed-timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.failure | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric |  |   0 
action_result.data.\*.attributes.last_analysis_stats.type-unsupported | numeric |  |   16 
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric |  |   59 
action_result.data.\*.attributes.last_modification_date | numeric |  |   1613635210 
action_result.data.\*.attributes.last_submission_date | numeric |  |   1613635130 
action_result.data.\*.attributes.magic | string |  |   a python2.7\\015script text executable 
action_result.data.\*.attributes.md5 | string |  `md5`  |   2e65153f2c49c91a0206ee7a8c00e659 
action_result.data.\*.attributes.meaningful_name | string |  |   update_cr.py 
action_result.data.\*.attributes.names | string |  |   update_cr.py 
action_result.data.\*.attributes.packers.F-PROT | string |  |   appended, docwrite 
action_result.data.\*.attributes.pdf_info.\* | numeric |  |   0 
action_result.data.\*.attributes.pe_info.entry_point | numeric |  |   176128 
action_result.data.\*.attributes.pe_info.imphash | string |  |   6bff2c73afd9249c4261ecfba6ff33c3 
action_result.data.\*.attributes.pe_info.import_list.\*.library_name | string |  |   MSVCP60.dll 
action_result.data.\*.attributes.pe_info.machine_type | numeric |  |   332 
action_result.data.\*.attributes.pe_info.overlay.\* | string |  |   xyz 
action_result.data.\*.attributes.pe_info.resource_details.\*.chi2 | numeric |  |   33203.078125 
action_result.data.\*.attributes.pe_info.resource_details.\*.entropy | numeric |  |   1.802635908126831 
action_result.data.\*.attributes.pe_info.resource_details.\*.filetype | string |  |   Data 
action_result.data.\*.attributes.pe_info.resource_details.\*.lang | string |  |   CHINESE SIMPLIFIED 
action_result.data.\*.attributes.pe_info.resource_details.\*.sha256 | string |  |   898cbcd6439db0ef0f912228ae647d10e15a014b8ce40dd164fa30290913227d 
action_result.data.\*.attributes.pe_info.resource_details.\*.type | string |  |   RT_CURSOR 
action_result.data.\*.attributes.pe_info.resource_langs.CHINESE SIMPLIFIED | numeric |  |   8 
action_result.data.\*.attributes.pe_info.resource_types.RT_BITMAP | numeric |  |   4 
action_result.data.\*.attributes.pe_info.resource_types.RT_CURSOR | numeric |  |   1 
action_result.data.\*.attributes.pe_info.resource_types.RT_GROUP_CURSOR | numeric |  |   1 
action_result.data.\*.attributes.pe_info.resource_types.RT_MENU | numeric |  |   1 
action_result.data.\*.attributes.pe_info.resource_types.RT_VERSION | numeric |  |   1 
action_result.data.\*.attributes.pe_info.rich_pe_header_hash | string |  |   9f82b368167a185aba138b2846e0b906 
action_result.data.\*.attributes.pe_info.sections.\*.chi2 | numeric |  |   672207.13 
action_result.data.\*.attributes.pe_info.sections.\*.entropy | numeric |  |   6.46 
action_result.data.\*.attributes.pe_info.sections.\*.flags | string |  |   rx 
action_result.data.\*.attributes.pe_info.sections.\*.md5 | string |  |   0bf0048782ea3987560f91ce29f946f4 
action_result.data.\*.attributes.pe_info.sections.\*.name | string |  |   .text 
action_result.data.\*.attributes.pe_info.sections.\*.raw_size | numeric |  |   90112 
action_result.data.\*.attributes.pe_info.sections.\*.virtual_address | numeric |  |   4096 
action_result.data.\*.attributes.pe_info.sections.\*.virtual_size | numeric |  |   90112 
action_result.data.\*.attributes.pe_info.timestamp | numeric |  |   1259933759 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.count | numeric |  |   16 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.value | string |  |   virus 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.count | numeric |  |   32 
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.value | string |  |   parite 
action_result.data.\*.attributes.popular_threat_classification.suggested_threat_label | string |  |   virus.parite/pate 
action_result.data.\*.attributes.reputation | numeric |  |   0 
action_result.data.\*.attributes.sandbox_verdicts.Lastline.\* | string |  |   xyz 
action_result.data.\*.attributes.sandbox_verdicts.Tencent HABO.\* | string |  |   xyz 
action_result.data.\*.attributes.sha1 | string |  `sha1`  |   6802169a19142292710254cde97df84e46dfe33a 
action_result.data.\*.attributes.sha256 | string |  `sha256`  |   e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.attributes.signature_info.\* | string |  |   xyz 
action_result.data.\*.attributes.size | numeric |  |   6285 
action_result.data.\*.attributes.ssdeep | string |  |   192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygi6OLxgUHzYu7ThPBLkv:pq7Mgg0/NdMu/1BLkv 
action_result.data.\*.attributes.tags | string |  |   python 
action_result.data.\*.attributes.times_submitted | numeric |  |   13 
action_result.data.\*.attributes.tlsh | string |  |   T1F7D10E05AC5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC 
action_result.data.\*.attributes.total_votes.harmless | numeric |  |   0 
action_result.data.\*.attributes.total_votes.malicious | numeric |  |   0 
action_result.data.\*.attributes.trid.\*.file_type | string |  |   Unix-like shebang (var.1) (gen) 
action_result.data.\*.attributes.trid.\*.probability | numeric |  |   100 
action_result.data.\*.attributes.type_description | string |  |   Python 
action_result.data.\*.attributes.type_extension | string |  |   py 
action_result.data.\*.attributes.type_tag | string |  |   python 
action_result.data.\*.attributes.unique_sources | numeric |  |   1 
action_result.data.\*.attributes.vhash | string |  |   7596fdd04dba990373ab2f3da0c7dd3f 
action_result.data.\*.data.attributes.date | numeric |  |   1613651763 
action_result.data.\*.data.attributes.results.\*.category | string |  |   undetected 
action_result.data.\*.data.attributes.results.\*.engine_name | string |  |   CMC 
action_result.data.\*.data.attributes.results.\*.engine_update | string |  |   20210218 
action_result.data.\*.data.attributes.results.\*.engine_version | string |  |   2.10.2019.1 
action_result.data.\*.data.attributes.results.\*.method | string |  |   blacklist 
action_result.data.\*.data.attributes.results.\*.result | string |  |  
action_result.data.\*.data.attributes.stats.confirmed-timeout | numeric |  |   0 
action_result.data.\*.data.attributes.stats.failure | numeric |  |   0 
action_result.data.\*.data.attributes.stats.harmless | numeric |  |   0 
action_result.data.\*.data.attributes.stats.malicious | numeric |  |   0 
action_result.data.\*.data.attributes.stats.suspicious | numeric |  |   0 
action_result.data.\*.data.attributes.stats.timeout | numeric |  |   0 
action_result.data.\*.data.attributes.stats.type-unsupported | numeric |  |   16 
action_result.data.\*.data.attributes.stats.undetected | numeric |  |   59 
action_result.data.\*.data.attributes.status | string |  |   completed 
action_result.data.\*.data.id | string |  `virustotal scan id`  |   MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw== 
action_result.data.\*.data.type | string |  |   analysis 
action_result.data.\*.id | string |  `sha256`  |   e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.links.self | string |  `url`  |   https://www.virustotal.com/api/v3/files/e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.meta.file_info.md5 | string |  `md5`  |   2e65153f2c49c91a0206ee7a8c00e659 
action_result.data.\*.meta.file_info.name | string |  |   update_cr.py 
action_result.data.\*.meta.file_info.sha1 | string |  `sha1`  |   6802169a19142292710254cde97df84e46dfe33a 
action_result.data.\*.meta.file_info.sha256 | string |  `sha256`  |   e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe 
action_result.data.\*.meta.file_info.size | numeric |  |   6285 
action_result.data.\*.type | string |  |   file 
action_result.summary.harmless | numeric |  |   0 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.scan_id | string |  `virustotal scan id`  |   9 
action_result.summary.scan_id | string |  |   MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw== 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   59 
action_result.message | string |  |   Scan id: MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw==, Harmless: 0, Malicious: 0, Suspicious: 0, Undetected: 59 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get report'
Get the results using the scan id from a detonate file or detonate url action

Type: **investigate**  
Read only: **True**

For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan_id** |  required  | Scan ID | string |  `virustotal scan id` 
**wait_time** |  optional  | Number of seconds to wait | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.scan_id | string |  `virustotal scan id`  |   u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 
action_result.parameter.wait_time | numeric |  |   10 
action_result.data.\*.data.attributes.date | numeric |  |   1613467266 
action_result.data.\*.data.attributes.results.\*.category | string |  |   harmless 
action_result.data.\*.data.attributes.results.\*.engine_name | string |  |   CRDF 
action_result.data.\*.data.attributes.results.\*.engine_update | string |  |   20210218 
action_result.data.\*.data.attributes.results.\*.engine_version | string |  |   2.10.2019.1 
action_result.data.\*.data.attributes.results.\*.method | string |  |   blacklist 
action_result.data.\*.data.attributes.results.\*.result | string |  |   clean 
action_result.data.\*.data.attributes.stats.harmless | numeric |  |   76 
action_result.data.\*.data.attributes.stats.malicious | numeric |  |   0 
action_result.data.\*.data.attributes.stats.suspicious | numeric |  |   0 
action_result.data.\*.data.attributes.stats.timeout | numeric |  |   0 
action_result.data.\*.data.attributes.stats.undetected | numeric |  |   7 
action_result.data.\*.data.attributes.status | string |  |   completed 
action_result.data.\*.data.id | string |  |   u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 
action_result.data.\*.data.links.self | string |  `url`  |   https://www.virustotal.com/api/v3/analyses/u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 
action_result.data.\*.data.type | string |  |   analysis 
action_result.data.\*.meta.file_info.sha256 | string |  |   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 
action_result.data.\*.meta.url_info.id | string |  `sha256`  |   114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488 
action_result.data.\*.meta.url_info.url | string |  |   http://shinedezign.tk/ 
action_result.summary.harmless | numeric |  |   76 
action_result.summary.malicious | numeric |  |   0 
action_result.summary.scan_id | string |  |   u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266 
action_result.summary.suspicious | numeric |  |   0 
action_result.summary.undetected | numeric |  |   7 
action_result.message | string |  |   Scan id: u-114fb86b9b4e868f8bac2249eb5c444b545f0240c3dadd23312a0bc1622b5488-1613467266, Harmless: 76, Malicious: 0, Suspicious: 0, Undetected: 7 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get cached entries'
Get listing of cached entries

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.\*.date_added | string |  |  
action_result.data.\*.date_expires | string |  |  
action_result.data.\*.key | string |  |  
action_result.data.\*.seconds_left | numeric |  |  
action_result.summary.count | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'clear cache'
Clear all cached entries

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.status | string |  |  
action_result.summary.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  