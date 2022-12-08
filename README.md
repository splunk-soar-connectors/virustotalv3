[comment]: # "Auto-generated SOAR connector documentation"
# VirusTotal v3

Publisher: Splunk  
Connector Version: 1\.5\.0  
Product Vendor: VirusTotal  
Product Name: VirusTotal v3  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.5  

This app integrates with the VirusTotal cloud to implement investigative and reputation actions using v3 APIs

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2021-2022 Splunk Inc."
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a VirusTotal v3 asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  required  | password | VirusTotal API key
**poll\_interval** |  optional  | numeric | Number of minutes to poll for a detonation result \(Default\: 5\)
**waiting\_time** |  optional  | numeric | Number of seconds to wait before polling for a detonation result \(Default\: 0\)
**rate\_limit** |  optional  | boolean | Limit number of requests to 4 per minute
**timeout** |  optional  | numeric | Request Timeout \(Default\: 30 seconds\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[domain reputation](#action-domain-reputation) - Queries VirusTotal for domain info  
[file reputation](#action-file-reputation) - Queries VirusTotal for file reputation info  
[get file](#action-get-file) - Downloads a file from VirusTotal and adds it to the vault  
[ip reputation](#action-ip-reputation) - Queries VirusTotal for IP info  
[url reputation](#action-url-reputation) - Queries VirusTotal for URL info  
[detonate url](#action-detonate-url) - Load a URL to Virus Total and retrieve analysis results  
[detonate file](#action-detonate-file) - Upload a file to Virus Total and retrieve the analysis results  
[get report](#action-get-report) - Get the results using the scan id from a detonate file or detonate url action  

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
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.attributes\.categories\.BitDefender | string | 
action\_result\.data\.\*\.attributes\.categories\.Comodo Valkyrie Verdict | string | 
action\_result\.data\.\*\.attributes\.categories\.Dr\.Web | string | 
action\_result\.data\.\*\.attributes\.categories\.Forcepoint ThreatSeeker | string | 
action\_result\.data\.\*\.attributes\.categories\.Sophos | string | 
action\_result\.data\.\*\.attributes\.categories\.alphaMountain\.ai | string | 
action\_result\.data\.\*\.attributes\.categories\.sophos | string | 
action\_result\.data\.\*\.attributes\.creation\_date | numeric | 
action\_result\.data\.\*\.attributes\.jarm | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.vendor | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.category | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.method | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.result | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.suspicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.undetected | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.expire | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.flag | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.minimum | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.priority | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.refresh | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.retry | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.rname | string | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.serial | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.tag | string | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.ttl | numeric | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.type | string | 
action\_result\.data\.\*\.attributes\.last\_dns\_records\.\*\.value | string |  `ip` 
action\_result\.data\.\*\.attributes\.last\_dns\_records\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.cert\_signature\.signature | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.cert\_signature\.signature\_algorithm | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.1\.3\.6\.1\.4\.1\.11129\.2\.4\.2 | string |  `sha256` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.CA | boolean | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.authority\_key\_identifier\.keyid | string |  `sha1` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.ca\_information\_access\.CA Issuers | string |  `url` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.ca\_information\_access\.OCSP | string |  `url` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.crl\_distribution\_points | string |  `url` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.extended\_key\_usage | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.key\_usage | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.subject\_alternative\_name | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.subject\_key\_identifier | string |  `sha1` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.issuer\.C | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.issuer\.CN | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.issuer\.O | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.issuer\.OU | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.algorithm | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.ec\.oid | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.ec\.pub | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.serial\_number | string |  `md5` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.signature\_algorithm | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.size | numeric | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.subject\.C | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.subject\.CN | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.subject\.L | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.subject\.O | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.subject\.ST | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.thumbprint | string |  `sha1` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.thumbprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.validity\.not\_after | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.validity\.not\_before | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.version | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_modification\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_update\_date | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Alexa\.rank | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Alexa\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Cisco Umbrella\.rank | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Cisco Umbrella\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Majestic\.rank | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Majestic\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Quantcast\.rank | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Quantcast\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Statvoo\.rank | numeric | 
action\_result\.data\.\*\.attributes\.popularity\_ranks\.Statvoo\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.registrar | string | 
action\_result\.data\.\*\.attributes\.reputation | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.whois | string | 
action\_result\.data\.\*\.attributes\.whois\_date | numeric | 
action\_result\.data\.\*\.id | string |  `domain` 
action\_result\.data\.\*\.links\.self | string |  `url` 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Queries VirusTotal for file reputation info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to query | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.attributes\.authentihash | string | 
action\_result\.data\.\*\.attributes\.creation\_date | numeric | 
action\_result\.data\.\*\.attributes\.first\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.vendor | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.category | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_update | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_version | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.method | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.result | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.confirmed\-timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.failure | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.suspicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.type\-unsupported | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.undetected | numeric | 
action\_result\.data\.\*\.attributes\.last\_modification\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.magic | string | 
action\_result\.data\.\*\.attributes\.md5 | string |  `md5` 
action\_result\.data\.\*\.attributes\.meaningful\_name | string | 
action\_result\.data\.\*\.attributes\.names | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.entry\_point | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.imphash | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.import\_list\.\*\.library\_name | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.machine\_type | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.chi2 | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.entropy | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.filetype | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.lang | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.sha256 | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.type | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_langs\.ENGLISH US | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_langs\.RUSSIAN | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_BITMAP | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_DIALOG | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_MANIFEST | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_MENU | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_VERSION | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.rich\_pe\_header\_hash | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.chi2 | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.entropy | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.flags | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.md5 | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.raw\_size | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.virtual\_address | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.virtual\_size | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_category\.\*\.count | numeric | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_category\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_name\.\*\.count | numeric | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_name\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.suggested\_threat\_label | string | 
action\_result\.data\.\*\.attributes\.reputation | numeric | 
action\_result\.data\.\*\.attributes\.sandbox\_verdicts\.Tencent HABO\.\* | string | 
action\_result\.data\.\*\.attributes\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.attributes\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.attributes\.signature\_info\.\* | string | 
action\_result\.data\.\*\.attributes\.size | numeric | 
action\_result\.data\.\*\.attributes\.ssdeep | string | 
action\_result\.data\.\*\.attributes\.tags | string | 
action\_result\.data\.\*\.attributes\.times\_submitted | numeric | 
action\_result\.data\.\*\.attributes\.tlsh | string | 
action\_result\.data\.\*\.attributes\.total\_votes\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.trid\.\*\.file\_type | string | 
action\_result\.data\.\*\.attributes\.trid\.\*\.probability | numeric | 
action\_result\.data\.\*\.attributes\.type\_description | string | 
action\_result\.data\.\*\.attributes\.type\_extension | string | 
action\_result\.data\.\*\.attributes\.type\_tag | string | 
action\_result\.data\.\*\.attributes\.unique\_sources | numeric | 
action\_result\.data\.\*\.attributes\.vhash | string | 
action\_result\.data\.\*\.id | string |  `sha256` 
action\_result\.data\.\*\.links\.self | string |  `url` 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Downloads a file from VirusTotal and adds it to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file to get | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Queries VirusTotal for IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.attributes\.as\_owner | string | 
action\_result\.data\.\*\.attributes\.asn | numeric | 
action\_result\.data\.\*\.attributes\.continent | string | 
action\_result\.data\.\*\.attributes\.country | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_context\.\*\.detail | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_context\.\*\.severity | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_context\.\*\.source | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_context\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.crowdsourced\_context\.\*\.title | string | 
action\_result\.data\.\*\.attributes\.jarm | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.vendor | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.category | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.method | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.result | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.suspicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.undetected | numeric | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.cert\_signature\.signature | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.cert\_signature\.signature\_algorithm | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.1\.3\.6\.1\.4\.1\.11129\.2\.4\.2 | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.CA | boolean | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.authority\_key\_identifier\.keyid | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.ca\_information\_access\.CA Issuers | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.ca\_information\_access\.OCSP | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.extensions\.subject\_key\_identifier | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.issuer\.\* | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.algorithm | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.rsa\.exponent | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.rsa\.key\_size | numeric | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.public\_key\.rsa\.modulus | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.serial\_number | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.signature\_algorithm | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.size | numeric | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.subject\.CN | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.thumbprint | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.thumbprint\_sha256 | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.validity\.not\_after | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.validity\.not\_before | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\.version | string | 
action\_result\.data\.\*\.attributes\.last\_https\_certificate\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_modification\_date | numeric | 
action\_result\.data\.\*\.attributes\.network | string | 
action\_result\.data\.\*\.attributes\.regional\_internet\_registry | string | 
action\_result\.data\.\*\.attributes\.reputation | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.whois | string | 
action\_result\.data\.\*\.attributes\.whois\_date | numeric | 
action\_result\.data\.\*\.id | string |  `ip` 
action\_result\.data\.\*\.links\.self | string |  `url` 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Queries VirusTotal for URL info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.attributes\.categories\.\* | string | 
action\_result\.data\.\*\.attributes\.categories\.Dr\.Web | string | 
action\_result\.data\.\*\.attributes\.categories\.alphaMountain\.ai | string | 
action\_result\.data\.\*\.attributes\.first\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.vendor | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.category | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.method | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.result | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.suspicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.undetected | numeric | 
action\_result\.data\.\*\.attributes\.last\_final\_url | string | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_code | numeric | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_content\_length | numeric | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_content\_sha256 | string | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_cookies\.\* | string | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_headers\.\* | string | 
action\_result\.data\.\*\.attributes\.last\_modification\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.reputation | numeric | 
action\_result\.data\.\*\.attributes\.times\_submitted | numeric | 
action\_result\.data\.\*\.attributes\.title | string | 
action\_result\.data\.\*\.attributes\.total\_votes\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.trackers\.ScoreCard Research Beacon\.\*\.id | string | 
action\_result\.data\.\*\.attributes\.trackers\.ScoreCard Research Beacon\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.trackers\.ScoreCard Research Beacon\.\*\.url | string | 
action\_result\.data\.\*\.attributes\.trackers\.Yahoo Dot Tags\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.trackers\.Yahoo Dot Tags\.\*\.url | string | 
action\_result\.data\.\*\.attributes\.url | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.links\.self | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.scan\_id | string |  `virustotal scan id` 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Load a URL to Virus Total and retrieve analysis results

Type: **investigate**  
Read only: **True**

<b>detonate url</b> will send a URL to Virus Total for analysis\. Virus Total, however, takes an indefinite amount of time to complete this scan\. This action will poll for the results for a short amount of time\. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>\. This should be used with the <b>get report</b> action to finish the scan\.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results\.<br/>Wait time parameter will be considered only if the given URL has not been previously submitted to the VirusTotal Server\. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url`  `domain` 
**wait\_time** |  optional  | Number of seconds to wait | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.parameter\.wait\_time | numeric | 
action\_result\.data\.\*\.attributes\.categories\.\* | string | 
action\_result\.data\.\*\.attributes\.categories\.Dr\.Web | string | 
action\_result\.data\.\*\.attributes\.first\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.vendor | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.category | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.method | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.result | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.suspicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.undetected | numeric | 
action\_result\.data\.\*\.attributes\.last\_final\_url | string | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_code | numeric | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_content\_length | numeric | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_content\_sha256 | string | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_cookies\.\* | string | 
action\_result\.data\.\*\.attributes\.last\_http\_response\_headers\.\* | string | 
action\_result\.data\.\*\.attributes\.last\_modification\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.reputation | numeric | 
action\_result\.data\.\*\.attributes\.times\_submitted | numeric | 
action\_result\.data\.\*\.attributes\.title | string | 
action\_result\.data\.\*\.attributes\.total\_votes\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.url | string | 
action\_result\.data\.\*\.data\.attributes\.date | numeric | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.category | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.method | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.result | string | 
action\_result\.data\.\*\.data\.attributes\.stats\.harmless | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.malicious | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.suspicious | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.timeout | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.undetected | numeric | 
action\_result\.data\.\*\.data\.attributes\.status | string | 
action\_result\.data\.\*\.data\.id | string |  `virustotal scan id` 
action\_result\.data\.\*\.data\.type | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.links\.self | string | 
action\_result\.data\.\*\.meta\.url\_info\.id | string |  `sha256` 
action\_result\.data\.\*\.meta\.url\_info\.url | string |  `url` 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.scan\_id | string |  `virustotal scan id` 
action\_result\.summary\.scan\_id | string | 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate file'
Upload a file to Virus Total and retrieve the analysis results

Type: **investigate**  
Read only: **True**

<b>detonate file</b> will send a file to Virus Total for analysis\. Virus Total, however, takes an indefinite amount of time to complete this scan\. This action will poll for the results for a short amount of time\. If it cannot get the finished results in this amount of time, it will fail and in the summary it will return the <b>scan id</b>\. This should be used with the <b>get report</b> action to finish the scan\.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results\.<br/>Wait time parameter will be considered only if the given file has not been previously submitted to the VirusTotal Server\. For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | The Vault ID of the file to scan | string |  `vault id`  `sha1` 
**wait\_time** |  optional  | Number of seconds to wait | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.parameter\.wait\_time | numeric | 
action\_result\.data\.\*\.attributes\.androguard\.AndroguardVersion | string | 
action\_result\.data\.\*\.attributes\.androguard\.AndroidApplication | numeric | 
action\_result\.data\.\*\.attributes\.androguard\.AndroidApplicationError | boolean | 
action\_result\.data\.\*\.attributes\.androguard\.AndroidApplicationInfo | string | 
action\_result\.data\.\*\.attributes\.androguard\.AndroidVersionCode | string | 
action\_result\.data\.\*\.attributes\.androguard\.AndroidVersionName | string | 
action\_result\.data\.\*\.attributes\.androguard\.MinSdkVersion | string | 
action\_result\.data\.\*\.attributes\.androguard\.Package | string | 
action\_result\.data\.\*\.attributes\.androguard\.RiskIndicator\.APK\.\* | numeric | 
action\_result\.data\.\*\.attributes\.androguard\.RiskIndicator\.PERM\.\* | numeric | 
action\_result\.data\.\*\.attributes\.androguard\.TargetSdkVersion | string | 
action\_result\.data\.\*\.attributes\.androguard\.VTAndroidInfo | numeric | 
action\_result\.data\.\*\.attributes\.androguard\.certificate\.Issuer\.\* | string | 
action\_result\.data\.\*\.attributes\.androguard\.certificate\.Subject\.\* | string | 
action\_result\.data\.\*\.attributes\.androguard\.certificate\.serialnumber | string | 
action\_result\.data\.\*\.attributes\.androguard\.certificate\.thumbprint | string | 
action\_result\.data\.\*\.attributes\.androguard\.certificate\.validfrom | string | 
action\_result\.data\.\*\.attributes\.androguard\.certificate\.validto | string | 
action\_result\.data\.\*\.attributes\.androguard\.main\_activity | string | 
action\_result\.data\.\*\.attributes\.androguard\.permission\_details\.android\.permission\.\*\.full\_description | string | 
action\_result\.data\.\*\.attributes\.androguard\.permission\_details\.android\.permission\.\*\.permission\_type | string | 
action\_result\.data\.\*\.attributes\.androguard\.permission\_details\.android\.permission\.\*\.short\_description | string | 
action\_result\.data\.\*\.attributes\.androguard\.permission\_details\.com\.ibm\.android\.analyzer\.test\.\*\.full\_description | string | 
action\_result\.data\.\*\.attributes\.androguard\.permission\_details\.com\.ibm\.android\.analyzer\.test\.\*\.permission\_type | string | 
action\_result\.data\.\*\.attributes\.androguard\.permission\_details\.com\.ibm\.android\.analyzer\.test\.\*\.short\_description | string | 
action\_result\.data\.\*\.attributes\.authentihash | string | 
action\_result\.data\.\*\.attributes\.bundle\_info\.lowest\_datetime | string | 
action\_result\.data\.\*\.attributes\.bundle\_info\.highest\_datetime | string | 
action\_result\.data\.\*\.attributes\.bundle\_info\.num\_children | numeric | 
action\_result\.data\.\*\.attributes\.bundle\_info\.uncompressed\_size | numeric | 
action\_result\.data\.\*\.attributes\.bundle\_info\.type | string | 
action\_result\.data\.\*\.attributes\.bundle\_info\.extensions\.\* | numeric | 
action\_result\.data\.\*\.attributes\.bundle\_info\.file\_types\.\* | numeric | 
action\_result\.data\.\*\.attributes\.bytehero\_info | string | 
action\_result\.data\.\*\.attributes\.creation\_date | numeric | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.alert\_severity | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.rule\_category | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.rule\_id | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.rule\_msg | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.rule\_raw | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.rule\_source | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_results\.\*\.rule\_url | string | 
action\_result\.data\.\*\.attributes\.crowdsourced\_ids\_stats\.\* | numeric | 
action\_result\.data\.\*\.attributes\.first\_seen\_itw\_date | numeric | 
action\_result\.data\.\*\.attributes\.first\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.html\_info\.iframes\.\*\.attributes\.\* | string | 
action\_result\.data\.\*\.attributes\.html\_info\.scripts\.\*\.attributes\.src | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.vendor | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.category | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_update | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.engine\_version | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.method | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_results\.\*\.result | string | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.confirmed\-timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.failure | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.suspicious | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.timeout | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.type\-unsupported | numeric | 
action\_result\.data\.\*\.attributes\.last\_analysis\_stats\.undetected | numeric | 
action\_result\.data\.\*\.attributes\.last\_modification\_date | numeric | 
action\_result\.data\.\*\.attributes\.last\_submission\_date | numeric | 
action\_result\.data\.\*\.attributes\.magic | string | 
action\_result\.data\.\*\.attributes\.md5 | string |  `md5` 
action\_result\.data\.\*\.attributes\.meaningful\_name | string | 
action\_result\.data\.\*\.attributes\.names | string | 
action\_result\.data\.\*\.attributes\.packers\.F\-PROT | string | 
action\_result\.data\.\*\.attributes\.pdf\_info\.\* | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.entry\_point | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.imphash | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.import\_list\.\*\.library\_name | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.machine\_type | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.overlay\.\* | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.chi2 | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.entropy | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.filetype | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.lang | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.sha256 | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_details\.\*\.type | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_langs\.CHINESE SIMPLIFIED | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_BITMAP | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_CURSOR | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_GROUP\_CURSOR | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_MENU | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.resource\_types\.RT\_VERSION | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.rich\_pe\_header\_hash | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.chi2 | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.entropy | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.flags | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.md5 | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.raw\_size | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.virtual\_address | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.sections\.\*\.virtual\_size | numeric | 
action\_result\.data\.\*\.attributes\.pe\_info\.timestamp | numeric | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_category\.\*\.count | numeric | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_category\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_name\.\*\.count | numeric | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.popular\_threat\_name\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.popular\_threat\_classification\.suggested\_threat\_label | string | 
action\_result\.data\.\*\.attributes\.reputation | numeric | 
action\_result\.data\.\*\.attributes\.sandbox\_verdicts\.Lastline\.\* | string | 
action\_result\.data\.\*\.attributes\.sandbox\_verdicts\.Tencent HABO\.\* | string | 
action\_result\.data\.\*\.attributes\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.attributes\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.attributes\.signature\_info\.\* | string | 
action\_result\.data\.\*\.attributes\.size | numeric | 
action\_result\.data\.\*\.attributes\.ssdeep | string | 
action\_result\.data\.\*\.attributes\.tags | string | 
action\_result\.data\.\*\.attributes\.times\_submitted | numeric | 
action\_result\.data\.\*\.attributes\.tlsh | string | 
action\_result\.data\.\*\.attributes\.total\_votes\.harmless | numeric | 
action\_result\.data\.\*\.attributes\.total\_votes\.malicious | numeric | 
action\_result\.data\.\*\.attributes\.trid\.\*\.file\_type | string | 
action\_result\.data\.\*\.attributes\.trid\.\*\.probability | numeric | 
action\_result\.data\.\*\.attributes\.type\_description | string | 
action\_result\.data\.\*\.attributes\.type\_extension | string | 
action\_result\.data\.\*\.attributes\.type\_tag | string | 
action\_result\.data\.\*\.attributes\.unique\_sources | numeric | 
action\_result\.data\.\*\.attributes\.vhash | string | 
action\_result\.data\.\*\.data\.attributes\.date | numeric | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.category | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_update | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_version | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.method | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.result | string | 
action\_result\.data\.\*\.data\.attributes\.stats\.confirmed\-timeout | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.failure | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.harmless | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.malicious | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.suspicious | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.timeout | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.type\-unsupported | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.undetected | numeric | 
action\_result\.data\.\*\.data\.attributes\.status | string | 
action\_result\.data\.\*\.data\.id | string |  `virustotal scan id` 
action\_result\.data\.\*\.data\.type | string | 
action\_result\.data\.\*\.id | string |  `sha256` 
action\_result\.data\.\*\.links\.self | string |  `url` 
action\_result\.data\.\*\.meta\.file\_info\.md5 | string |  `md5` 
action\_result\.data\.\*\.meta\.file\_info\.name | string | 
action\_result\.data\.\*\.meta\.file\_info\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.meta\.file\_info\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.meta\.file\_info\.size | numeric | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.scan\_id | string |  `virustotal scan id` 
action\_result\.summary\.scan\_id | string | 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Get the results using the scan id from a detonate file or detonate url action

Type: **investigate**  
Read only: **True**

For the wait time parameter, the priority will be given to the action parameter over the asset configuration parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan\_id** |  required  | Scan ID | string |  `virustotal scan id` 
**wait\_time** |  optional  | Number of seconds to wait | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.scan\_id | string |  `virustotal scan id` 
action\_result\.parameter\.wait\_time | numeric | 
action\_result\.data\.\*\.data\.attributes\.date | numeric | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.category | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_name | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_update | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.engine\_version | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.method | string | 
action\_result\.data\.\*\.data\.attributes\.results\.\*\.result | string | 
action\_result\.data\.\*\.data\.attributes\.stats\.harmless | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.malicious | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.suspicious | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.timeout | numeric | 
action\_result\.data\.\*\.data\.attributes\.stats\.undetected | numeric | 
action\_result\.data\.\*\.data\.attributes\.status | string | 
action\_result\.data\.\*\.data\.id | string | 
action\_result\.data\.\*\.data\.links\.self | string |  `url` 
action\_result\.data\.\*\.data\.type | string | 
action\_result\.data\.\*\.meta\.url\_info\.url | string | 
action\_result\.data\.\*\.meta\.file\_info\.sha256 | string | 
action\_result\.data\.\*\.meta\.url\_info\.id | string |  `sha256` 
action\_result\.summary\.harmless | numeric | 
action\_result\.summary\.malicious | numeric | 
action\_result\.summary\.scan\_id | string | 
action\_result\.summary\.suspicious | numeric | 
action\_result\.summary\.undetected | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 