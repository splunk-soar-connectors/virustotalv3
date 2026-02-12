# VirusTotal v3

Publisher: Splunk <br>
Connector Version: 2.0.5 <br>
Product Vendor: VirusTotal <br>
Product Name: VirusTotal v3 <br>
Minimum Product Version: 6.4.0

This app integrates with the VirusTotal cloud to implement investigative and reputation actions using v3 APIs

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

[test connectivity](#action-test-connectivity) - test connectivity <br>
[domain reputation](#action-domain-reputation) - Queries VirusTotal for domain info <br>
[make request](#action-make-request) - make request <br>
[file reputation](#action-file-reputation) - Queries VirusTotal for file reputation info <br>
[get file](#action-get-file) - Downloads a file from VirusTotal and adds it to the vault <br>
[ip reputation](#action-ip-reputation) - Queries VirusTotal for IP info <br>
[url reputation](#action-url-reputation) - Queries VirusTotal for URL info (run this action after running detonate url) <br>
[detonate url](#action-detonate-url) - Load a URL to Virus Total and retrieve analysis results <br>
[detonate file](#action-detonate-file) - Upload a file to Virus Total and retrieve the analysis results <br>
[get report](#action-get-report) - Get the results using the scan id from a detonate file or detonate url action <br>
[get cached entries](#action-get-cached-entries) - Get listing of cached entries <br>
[clear cache](#action-clear-cache) - Clear all cached entries <br>
[get quotas](#action-get-quotas) - Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'domain reputation'

Queries VirusTotal for domain info

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to query | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` | |
action_result.data.\*.id | string | `domain` | test.com |
action_result.data.\*.type | string | | domain |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.attributes.last_dns_records_date | numeric | `timestamp` | 1757503155 |
action_result.data.\*.attributes.jarm | string | | 29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae |
action_result.data.\*.attributes.last_analysis_date | numeric | `timestamp` | 1679467461 |
action_result.data.\*.attributes.creation_date | numeric | `timestamp` | 1613635130 |
action_result.data.\*.attributes.last_analysis_results.Acronis.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Acronis.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Acronis.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Acronis.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Abusix.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Abusix.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Abusix.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Abusix.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Axur.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Axur.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Axur.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Axur.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.AlienVault.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.AlienVault.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.AlienVault.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.AlienVault.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.AutoShun.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.AutoShun.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.AutoShun.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.AutoShun.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.BitDefender.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.BitDefender.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.BitDefender.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.BitDefender.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Bkav.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Bkav.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Bkav.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Bkav.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Blueliv.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Blueliv.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Blueliv.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Blueliv.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Certego.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Certego.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Certego.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Certego.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Cluster25.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Cluster25.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Cluster25.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Cluster25.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.CRDF.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.CRDF.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.CRDF.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.CRDF.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Cyan.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Cyan.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Cyan.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Cyan.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Cyble.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Cyble.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Cyble.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Cyble.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.CyRadar.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.CyRadar.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.CyRadar.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.CyRadar.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.DNS8.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.DNS8.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.DNS8.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.DNS8.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Ermes.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Ermes.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Ermes.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Ermes.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ESET.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ESET.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ESET.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ESET.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Fortinet.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Fortinet.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Fortinet.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Fortinet.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.G_Data.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.G_Data.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.G_Data.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.G_Data.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.IPsum.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.IPsum.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.IPsum.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.IPsum.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Lionic.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Lionic.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Lionic.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Lionic.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Lumu.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Lumu.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Lumu.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Lumu.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Malwared.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Malwared.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Malwared.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Malwared.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Mimecast.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Mimecast.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Mimecast.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Mimecast.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Netcraft.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Netcraft.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Netcraft.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Netcraft.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.PhishFort.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.PhishFort.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.PhishFort.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.PhishFort.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Phishtank.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Phishtank.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Phishtank.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Phishtank.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Quttera.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Quttera.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Quttera.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Quttera.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Scantitan.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Scantitan.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Scantitan.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Scantitan.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Seclookup.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Seclookup.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Seclookup.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Seclookup.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Sophos.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Sophos.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Sophos.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Sophos.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Spam404.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Spam404.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Spam404.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Spam404.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Trustwave.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Trustwave.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Trustwave.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Trustwave.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Underworld.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Underworld.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Underworld.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Underworld.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.URLhaus.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.URLhaus.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.URLhaus.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.URLhaus.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.URLQuery.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.URLQuery.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.URLQuery.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.URLQuery.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.VIPRE.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.VIPRE.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.VIPRE.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.VIPRE.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ViriBack.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ViriBack.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ViriBack.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ViriBack.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Webroot.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Webroot.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Webroot.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Webroot.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.securolytics.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.securolytics.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.securolytics.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.securolytics.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.zvelo.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.zvelo.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.zvelo.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.zvelo.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.ZeroFox.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.ZeroFox.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.ZeroFox.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.ZeroFox.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.total_votes.harmless | numeric | | |
action_result.data.\*.attributes.total_votes.malicious | numeric | | |
action_result.data.\*.attributes.whois_date | numeric | `timestamp` | 1613635130 |
action_result.data.\*.attributes.expiration_date | numeric | `timestamp` | 1613635130 |
action_result.data.\*.attributes.last_modification_date | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.whois | string | | Test data Domain Name: TEST.COM Registry Domain ID: 9999999999_DOMAIN_COM-VRSN Registrar WHOIS Server: whois.test.com Registrar URL: http://www.test.com Updated Date: 2021-02-17T07:07:07Z Creation Date: 2021-02-17T07:07:07Z Registry Expiry Date: 2022-02-17T07:07:07Z Registrar: Test Registrar, Inc. Registrar IANA ID: 9999 Registrar Abuse Contact Email: |
action_result.data.\*.attributes.reputation | numeric | | |
action_result.data.\*.attributes.last_dns_records.\*.type | string | | A |
action_result.data.\*.attributes.last_dns_records.\*.value | string | | 192.0.2.1 |
action_result.data.\*.attributes.last_dns_records.\*.ttl | numeric | | |
action_result.data.\*.attributes.last_dns_records.\*.rname | string | | |
action_result.data.\*.attributes.last_dns_records.\*.serial | numeric | | |
action_result.data.\*.attributes.last_dns_records.\*.refresh | numeric | | |
action_result.data.\*.attributes.last_dns_records.\*.retry | numeric | | |
action_result.data.\*.attributes.last_dns_records.\*.expire | numeric | | |
action_result.data.\*.attributes.last_dns_records.\*.minimum | numeric | | |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature | string | | |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature_algorithm | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.authority_key_identifier.keyid | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_key_identifier | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_alternative_name.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.certificate_policies.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.key_usage.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.extended_key_usage.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.crl_distribution_points.\* | string | `url` | |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.CA_Issuers | string | `url` | |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.OCSP | string | `url` | |
action_result.data.\*.attributes.last_https_certificate.extensions.CA | boolean | | True False |
action_result.data.\*.attributes.last_https_certificate.extensions.1_3_6_1_4_1_11129_2_4_2 | string | | |
action_result.data.\*.attributes.last_https_certificate.validity.not_before | string | `date` | |
action_result.data.\*.attributes.last_https_certificate.validity.not_after | string | `date` | |
action_result.data.\*.attributes.last_https_certificate.size | numeric | | |
action_result.data.\*.attributes.last_https_certificate.version | string | | |
action_result.data.\*.attributes.last_https_certificate.public_key.algorithm | string | | |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.exponent | string | | |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.key_size | numeric | | |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.modulus | string | | |
action_result.data.\*.attributes.last_https_certificate.thumbprint_sha256 | string | | |
action_result.data.\*.attributes.last_https_certificate.thumbprint | string | | |
action_result.data.\*.attributes.last_https_certificate.serial_number | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.CN | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.O | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.C | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.L | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.ST | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.CN | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.O | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.C | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.L | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.ST | string | | |
action_result.data.\*.attributes.tld | string | | com |
action_result.data.\*.attributes.last_https_certificate_date | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | |
action_result.data.\*.attributes.registrar | string | | |
action_result.data.\*.attributes.categories.alphaMountain_ai | string | | |
action_result.data.\*.attributes.categories.BitDefender | string | | |
action_result.data.\*.attributes.categories.Xcitium_Verdict_Cloud | string | | |
action_result.data.\*.attributes.categories.Sophos | string | | |
action_result.data.\*.attributes.categories.Forcepoint_ThreatSeeker | string | | |
action_result.data.\*.attributes.popularity_ranks.Majestic.rank | numeric | | |
action_result.data.\*.attributes.popularity_ranks.Majestic.timestamp | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.popularity_ranks.Statvoo.rank | numeric | | |
action_result.data.\*.attributes.popularity_ranks.Statvoo.timestamp | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.popularity_ranks.Alexa.rank | numeric | | |
action_result.data.\*.attributes.popularity_ranks.Alexa.timestamp | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.popularity_ranks.Cisco_Umbrella.rank | numeric | | |
action_result.data.\*.attributes.popularity_ranks.Cisco_Umbrella.timestamp | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.popularity_ranks.Quantcast.rank | numeric | | |
action_result.data.\*.attributes.popularity_ranks.Quantcast.timestamp | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.popularity_ranks.Cloudflare_Radar.rank | numeric | | |
action_result.data.\*.attributes.popularity_ranks.Cloudflare_Radar.timestamp | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.last_update_date | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.rdap.handle | string | | |
action_result.data.\*.attributes.rdap.ldh_name | string | | |
action_result.data.\*.attributes.rdap.events.\*.event_action | string | | |
action_result.data.\*.attributes.rdap.events.\*.event_date | string | `date` | |
action_result.data.\*.attributes.rdap.events.\*.event_actor | string | | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.events.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.notices.\*.title | string | | |
action_result.data.\*.attributes.rdap.notices.\*.description.\* | string | | |
action_result.data.\*.attributes.rdap.notices.\*.type | string | | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.notices.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.ldh_name | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.event_action | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.event_date | string | `date` | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.event_actor | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.events.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.object_class_name | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.status.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.handle | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.unicode_name | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.description.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.notices.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.lang | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.port43 | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.vcard_array.\*.name | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.vcard_array.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.vcard_array.\*.values.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.roles.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.description.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.remarks.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.event_action | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.event_date | string | `date` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.event_actor | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.events.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.handle | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.public_ids.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.public_ids.\*.identifier | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.port43 | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.networks.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.autnums.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.url | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.lang | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.entities.\*.rdap_conformance.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.description.\* | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.nameservers.\*.remarks.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.rdap_conformance.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.vcard_array.\*.name | string | | |
action_result.data.\*.attributes.rdap.entities.\*.vcard_array.\*.type | string | | |
action_result.data.\*.attributes.rdap.entities.\*.vcard_array.\*.values.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.roles.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.title | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.description.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.type | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.entities.\*.remarks.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.event_action | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.event_date | string | `date` | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.event_actor | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.entities.\*.events.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.handle | string | | |
action_result.data.\*.attributes.rdap.entities.\*.public_ids.\*.type | string | | |
action_result.data.\*.attributes.rdap.entities.\*.public_ids.\*.identifier | string | | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.entities.\*.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.port43 | string | | |
action_result.data.\*.attributes.rdap.entities.\*.networks.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.autnums.\* | string | | |
action_result.data.\*.attributes.rdap.entities.\*.url | string | `url` | |
action_result.data.\*.attributes.rdap.entities.\*.lang | string | | |
action_result.data.\*.attributes.rdap.entities.\*.rdap_conformance.\* | string | | |
action_result.data.\*.attributes.rdap.object_class_name | string | | |
action_result.data.\*.attributes.rdap.status.\* | string | | |
action_result.data.\*.attributes.rdap.secure_dns.zone_signed | boolean | | True False |
action_result.data.\*.attributes.rdap.secure_dns.delegation_signed | boolean | | True False |
action_result.data.\*.attributes.rdap.secure_dns.max_sig_life | numeric | | |
action_result.data.\*.attributes.rdap.secure_dns.ds_data.\* | string | | |
action_result.data.\*.attributes.rdap.secure_dns.key_data.\* | string | | |
action_result.data.\*.attributes.rdap.port43 | string | | |
action_result.data.\*.attributes.rdap.unicode_name | string | | |
action_result.data.\*.attributes.rdap.punycode | string | | |
action_result.data.\*.attributes.rdap.type | string | | |
action_result.data.\*.attributes.rdap.links.\*.value | string | `url` | |
action_result.data.\*.attributes.rdap.links.\*.rel | string | | |
action_result.data.\*.attributes.rdap.links.\*.href | string | `url` | |
action_result.data.\*.attributes.rdap.links.\*.type | string | | |
action_result.data.\*.attributes.rdap.links.\*.title | string | | |
action_result.data.\*.attributes.rdap.links.\*.media | string | | |
action_result.data.\*.attributes.rdap.links.\*.href_lang.\* | string | | |
action_result.data.\*.attributes.rdap.switch_name | string | | |
action_result.data.\*.attributes.rdap.public_ids.\*.type | string | | |
action_result.data.\*.attributes.rdap.public_ids.\*.identifier | string | | |
action_result.data.\*.attributes.rdap.lang | string | | |
action_result.data.\*.attributes.rdap.remarks.\* | string | | |
action_result.data.\*.attributes.rdap.nask0_state | string | | |
action_result.data.\*.attributes.rdap.variants.\* | string | | |
action_result.data.\*.attributes.tags.\* | string | | |
action_result.summary.harmless | numeric | | |
action_result.summary.malicious | numeric | | |
action_result.summary.suspicious | numeric | | |
action_result.summary.undetected | numeric | | |
action_result.summary.source | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

make request

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Valid VirusTotal endpoint that will be appended to the end of the base url, https://www.virustotal.com/api/v3. An example of a valid endpoint is 'domains/example.com'. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is False. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 |
action_result.data.\*.response_body | string | | Success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'file reputation'

Queries VirusTotal for file reputation info

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | File hash to query | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | |
action_result.data.\*.id | string | `sha256` | |
action_result.data.\*.type | string | | file |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.attributes.first_submission_date | numeric | `timestamp` | |
action_result.data.\*.attributes.known_distributors.distributors.\* | string | | |
action_result.data.\*.attributes.known_distributors.filenames.\* | string | | |
action_result.data.\*.attributes.known_distributors.products.\* | string | | |
action_result.data.\*.attributes.known_distributors.data_sources.\* | string | | |
action_result.data.\*.attributes.type_tag | string | | |
action_result.data.\*.attributes.md5 | string | `md5` | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.category | string | | malicious harmless suspicious |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.confidence | numeric | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.malware_classification.\* | string | | CLEAN |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.malware_names.\* | string | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.sandbox_name | string | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.category | string | | malicious harmless suspicious |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.confidence | numeric | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.malware_classification.\* | string | | CLEAN |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.malware_names.\* | string | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.sandbox_name | string | | |
action_result.data.\*.attributes.sha256 | string | `sha256` | |
action_result.data.\*.attributes.last_submission_date | numeric | `timestamp` | |
action_result.data.\*.attributes.trid.\*.file_type | string | | |
action_result.data.\*.attributes.trid.\*.probability | numeric | | |
action_result.data.\*.attributes.filecondis.raw_md5 | string | `md5` | |
action_result.data.\*.attributes.filecondis.dhash | string | `hash` | |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.confirmed_timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.failure | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.type_unsupported | numeric | | |
action_result.data.\*.attributes.ssdeep | string | | |
action_result.data.\*.attributes.type_description | string | | |
action_result.data.\*.attributes.size | numeric | | |
action_result.data.\*.attributes.magic | string | | |
action_result.data.\*.attributes.total_votes.harmless | numeric | | |
action_result.data.\*.attributes.total_votes.malicious | numeric | | |
action_result.data.\*.attributes.times_submitted | numeric | | |
action_result.data.\*.attributes.tags.\* | string | | |
action_result.data.\*.attributes.last_modification_date | numeric | `timestamp` | |
action_result.data.\*.attributes.meaningful_name | string | | |
action_result.data.\*.attributes.tlsh | string | | |
action_result.data.\*.attributes.first_seen_itw_date | numeric | `timestamp` | |
action_result.data.\*.attributes.last_analysis_date | numeric | `timestamp` | |
action_result.data.\*.attributes.sha1 | string | `sha1` | |
action_result.data.\*.attributes.reputation | numeric | | |
action_result.data.\*.attributes.unique_sources | numeric | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.category | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.method | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.result | string | | |
action_result.data.\*.attributes.last_analysis_results.MicroWorld_eScan.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ClamAV.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CTX.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Skyhigh.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ALYac.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwarebytes.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Zillya.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Sangfor.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.category | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.method | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.result | string | | |
action_result.data.\*.attributes.last_analysis_results.K7AntiVirus.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.category | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.method | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.result | string | | |
action_result.data.\*.attributes.last_analysis_results.K7GW.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CrowdStrike.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Baidu.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Symantec.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET_NOD32.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.category | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.method | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.result | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro_HouseCall.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Cynet.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.category | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.method | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.result | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.category | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.method | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.result | string | | |
action_result.data.\*.attributes.last_analysis_results.NANO_Antivirus.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SUPERAntiSpyware.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Rising.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.category | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.method | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.result | string | | |
action_result.data.\*.attributes.last_analysis_results.F_Secure.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.category | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.method | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.result | string | | |
action_result.data.\*.attributes.last_analysis_results.DrWeb.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.category | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.method | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.result | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.category | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.method | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.result | string | | |
action_result.data.\*.attributes.last_analysis_results.TrendMicro.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.category | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.method | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.result | string | | |
action_result.data.\*.attributes.last_analysis_results.McAfeeD.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Ikarus.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Jiangmin.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Google.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Avira.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Kingsoft.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Microsoft.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Acrabit.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ViRobot.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ZoneAlarm.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.category | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.method | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.result | string | | |
action_result.data.\*.attributes.last_analysis_results.GData.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Varist.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.category | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.method | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.result | string | | |
action_result.data.\*.attributes.last_analysis_results.AhnLab_V3.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.category | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.method | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.result | string | | |
action_result.data.\*.attributes.last_analysis_results.VBA32.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.category | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.method | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.result | string | | |
action_result.data.\*.attributes.last_analysis_results.TACHYON.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Zoner.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Tencent.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.category | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.method | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.result | string | | |
action_result.data.\*.attributes.last_analysis_results.TrellixENS.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.category | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.method | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.result | string | | |
action_result.data.\*.attributes.last_analysis_results.huorong.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.category | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.method | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.result | string | | |
action_result.data.\*.attributes.last_analysis_results.MaxSecure.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.category | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.method | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.result | string | | |
action_result.data.\*.attributes.last_analysis_results.AVG.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Panda.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.category | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.method | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.result | string | | |
action_result.data.\*.attributes.last_analysis_results.alibabacloud.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.category | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.method | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.result | string | | |
action_result.data.\*.attributes.last_analysis_results.VirIT.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CAT_QuickHeal.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Avast_Mobile.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SymantecMobileInsight.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.category | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.method | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.result | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefenderFalx.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.category | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.method | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.result | string | | |
action_result.data.\*.attributes.last_analysis_results.DeepInstinct.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Elastic.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.category | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.method | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.result | string | | |
action_result.data.\*.attributes.last_analysis_results.APEX.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Paloalto.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Trapmine.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Alibaba.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Cylance.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SentinelOne.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.category | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.method | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.result | string | | |
action_result.data.\*.attributes.last_analysis_results.tehtris.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustlook.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.category | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.method | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.result | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.vendor | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Nucleon.vendor | string | | |
action_result.data.\*.attributes.type_extension | string | | py |
action_result.data.\*.attributes.magika | string | | |
action_result.data.\*.attributes.type_tags.\* | string | | |
action_result.data.\*.attributes.names.\* | string | | |
action_result.data.\*.attributes.pdf_info.acroform | numeric | | |
action_result.data.\*.attributes.pdf_info.autoaction | numeric | | |
action_result.data.\*.attributes.pdf_info.embedded_file | numeric | | |
action_result.data.\*.attributes.pdf_info.encrypted | numeric | | |
action_result.data.\*.attributes.pdf_info.flash | numeric | | |
action_result.data.\*.attributes.pdf_info.header | string | | |
action_result.data.\*.attributes.pdf_info.javascript | numeric | | |
action_result.data.\*.attributes.pdf_info.jbig2_compression | numeric | | |
action_result.data.\*.attributes.pdf_info.js | numeric | | |
action_result.data.\*.attributes.pdf_info.num_endobj | numeric | | |
action_result.data.\*.attributes.pdf_info.num_endstream | numeric | | |
action_result.data.\*.attributes.pdf_info.num_launch_actions | numeric | | |
action_result.data.\*.attributes.pdf_info.num_obj | numeric | | |
action_result.data.\*.attributes.pdf_info.num_object_streams | numeric | | |
action_result.data.\*.attributes.pdf_info.num_pages | numeric | | |
action_result.data.\*.attributes.pdf_info.num_stream | numeric | | |
action_result.data.\*.attributes.pdf_info.openaction | numeric | | |
action_result.data.\*.attributes.pdf_info.startxref | numeric | | |
action_result.data.\*.attributes.pdf_info.suspicious_colors | numeric | | |
action_result.data.\*.attributes.pdf_info.trailer | numeric | | |
action_result.data.\*.attributes.pdf_info.xfa | numeric | | |
action_result.data.\*.attributes.pdf_info.xref | numeric | | |
action_result.data.\*.attributes.detectiteasy.filetype | string | | |
action_result.data.\*.attributes.detectiteasy.values.\*.info | string | | |
action_result.data.\*.attributes.detectiteasy.values.\*.name | string | | |
action_result.data.\*.attributes.detectiteasy.values.\*.type | string | | |
action_result.data.\*.attributes.detectiteasy.values.\*.version | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.age | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.guid | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.name | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.offset | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.signature | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.timestamp | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.fpo.functions | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.datatype | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.length | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.unicode | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.data | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.reserved | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.offset | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.reserved10.value | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.size | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.timestamp | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.type | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.type_str | string | | |
action_result.data.\*.attributes.pe_info.entry_point | numeric | | |
action_result.data.\*.attributes.pe_info.exports.\* | string | | |
action_result.data.\*.attributes.pe_info.imphash | string | | |
action_result.data.\*.attributes.pe_info.import_list.\*.imported_functions.\* | string | | |
action_result.data.\*.attributes.pe_info.import_list.\*.library_name | string | | |
action_result.data.\*.attributes.pe_info.machine_type | string | | |
action_result.data.\*.attributes.pe_info.overlay.chi2 | numeric | | |
action_result.data.\*.attributes.pe_info.overlay.entropy | numeric | | |
action_result.data.\*.attributes.pe_info.overlay.filetype | string | | |
action_result.data.\*.attributes.pe_info.overlay.md5 | string | `md5` | |
action_result.data.\*.attributes.pe_info.overlay.offset | numeric | | |
action_result.data.\*.attributes.pe_info.overlay.size | numeric | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.chi2 | numeric | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.entropy | numeric | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.filetype | string | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.lang | string | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.sha256 | string | `sha256` | |
action_result.data.\*.attributes.pe_info.resource_details.\*.type | string | | |
action_result.data.\*.attributes.pe_info.sections.\*.entropy | numeric | | |
action_result.data.\*.attributes.pe_info.sections.\*.md5 | string | `md5` | |
action_result.data.\*.attributes.pe_info.sections.\*.name | string | | |
action_result.data.\*.attributes.pe_info.sections.\*.raw_size | numeric | | |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_address | numeric | | |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_size | numeric | | |
action_result.data.\*.attributes.pe_info.timestamp | numeric | `timestamp` | |
action_result.data.\*.attributes.popular_threat_classification.suggested_threat_label | string | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.value | string | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.count | numeric | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.value | string | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get file'

Downloads a file from VirusTotal and adds it to the vault

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash of file to get | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'ip reputation'

Queries VirusTotal for IP info

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to query | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.data.\*.id | string | `ip` | 2.3.4.5 |
action_result.data.\*.type | string | | ip_address |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.attributes.as_owner | string | | |
action_result.data.\*.attributes.asn | numeric | | |
action_result.data.\*.attributes.network | string | `ip` | |
action_result.data.\*.attributes.country | string | | |
action_result.data.\*.attributes.continent | string | | |
action_result.data.\*.attributes.jarm | string | | |
action_result.data.\*.attributes.last_analysis_date | numeric | `timestamp` | |
action_result.data.\*.attributes.last_analysis_results.Acronis.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Acronis.result | string | | |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.category | string | | |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.method | string | | |
action_result.data.\*.attributes.last_analysis_results.0xSI_f33d.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Abusix.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Abusix.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Abusix.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Abusix.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ADMINUSLabs.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Axur.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Axur.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Axur.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Axur.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ChainPatrol.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Criminal_IP.result | string | | |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.category | string | | |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.method | string | | |
action_result.data.\*.attributes.last_analysis_results.AILabs_MONITORAPP.result | string | | |
action_result.data.\*.attributes.last_analysis_results.AlienVault.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.AlienVault.category | string | | |
action_result.data.\*.attributes.last_analysis_results.AlienVault.method | string | | |
action_result.data.\*.attributes.last_analysis_results.AlienVault.result | string | | |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.category | string | | |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.method | string | | |
action_result.data.\*.attributes.last_analysis_results.alphaMountain_ai.result | string | | |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.category | string | | |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.method | string | | |
action_result.data.\*.attributes.last_analysis_results.AlphaSOC.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Antiy_AVL.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ArcSight_Threat_Intelligence.result | string | | |
action_result.data.\*.attributes.last_analysis_results.AutoShun.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.AutoShun.category | string | | |
action_result.data.\*.attributes.last_analysis_results.AutoShun.method | string | | |
action_result.data.\*.attributes.last_analysis_results.AutoShun.result | string | | |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.category | string | | |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.method | string | | |
action_result.data.\*.attributes.last_analysis_results.benkow_cc.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Bfore_Ai_PreCrime.result | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.category | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.method | string | | |
action_result.data.\*.attributes.last_analysis_results.BitDefender.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Bkav.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Blueliv.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Blueliv.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Blueliv.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Blueliv.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Certego.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Certego.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Certego.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Certego.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Chong_Lua_Dao.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CINS_Army.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Cluster25.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Cluster25.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Cluster25.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Cluster25.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CRDF.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CRDF.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CRDF.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CRDF.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CSIS_Security_Group.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Snort_IP_sample_list.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CMC_Threat_Intelligence.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyan.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyan.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyan.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyan.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyble.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyble.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyble.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Cyble.result | string | | |
action_result.data.\*.attributes.last_analysis_results.CyRadar.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.CyRadar.category | string | | |
action_result.data.\*.attributes.last_analysis_results.CyRadar.method | string | | |
action_result.data.\*.attributes.last_analysis_results.CyRadar.result | string | | |
action_result.data.\*.attributes.last_analysis_results.DNS8.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.DNS8.category | string | | |
action_result.data.\*.attributes.last_analysis_results.DNS8.method | string | | |
action_result.data.\*.attributes.last_analysis_results.DNS8.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Dr_Web.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Ermes.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Ermes.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Ermes.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Ermes.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ESET.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ESTsecurity.result | string | | |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.category | string | | |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.method | string | | |
action_result.data.\*.attributes.last_analysis_results.EmergingThreats.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Emsisoft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Forcepoint_ThreatSeeker.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Fortinet.result | string | | |
action_result.data.\*.attributes.last_analysis_results.G_Data.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.G_Data.category | string | | |
action_result.data.\*.attributes.last_analysis_results.G_Data.method | string | | |
action_result.data.\*.attributes.last_analysis_results.G_Data.result | string | | |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.category | string | | |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.method | string | | |
action_result.data.\*.attributes.last_analysis_results.GCP_Abuse_Intelligence.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Google_Safebrowsing.result | string | | |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.category | string | | |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.method | string | | |
action_result.data.\*.attributes.last_analysis_results.GreenSnow.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Gridinsoft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Heimdal_Security.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Hunt_io_Intelligence.result | string | | |
action_result.data.\*.attributes.last_analysis_results.IPsum.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.IPsum.category | string | | |
action_result.data.\*.attributes.last_analysis_results.IPsum.method | string | | |
action_result.data.\*.attributes.last_analysis_results.IPsum.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Juniper_Networks.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Kaspersky.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Lionic.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Lumu.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Lumu.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Lumu.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Lumu.result | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.category | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.method | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwarePatrol.result | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.category | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.method | string | | |
action_result.data.\*.attributes.last_analysis_results.MalwareURL.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwared.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwared.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwared.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Malwared.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Mimecast.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Mimecast.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Mimecast.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Mimecast.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Netcraft.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Netcraft.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Netcraft.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Netcraft.result | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.category | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.method | string | | |
action_result.data.\*.attributes.last_analysis_results.OpenPhish.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishing_Database.result | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishFort.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishFort.category | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishFort.method | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishFort.result | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.category | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.method | string | | |
action_result.data.\*.attributes.last_analysis_results.PhishLabs.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishtank.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishtank.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishtank.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Phishtank.result | string | | |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.category | string | | |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.method | string | | |
action_result.data.\*.attributes.last_analysis_results.PREBYTES.result | string | | |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.category | string | | |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.method | string | | |
action_result.data.\*.attributes.last_analysis_results.PrecisionSec.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Quick_Heal.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Quttera.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Quttera.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Quttera.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Quttera.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SafeToOpen.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Sansec_eComscan.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Scantitan.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Scantitan.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Scantitan.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Scantitan.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SCUMWARE_org.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Seclookup.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Seclookup.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Seclookup.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Seclookup.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SecureBrain.result | string | | |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.category | string | | |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.method | string | | |
action_result.data.\*.attributes.last_analysis_results.SOCRadar.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Sophos.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Spam404.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Spam404.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Spam404.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Spam404.result | string | | |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.category | string | | |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.method | string | | |
action_result.data.\*.attributes.last_analysis_results.StopForumSpam.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Sucuri_SiteCheck.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ThreatHive.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Threatsourcing.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustwave.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustwave.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustwave.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Trustwave.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Underworld.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Underworld.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Underworld.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Underworld.result | string | | |
action_result.data.\*.attributes.last_analysis_results.URLhaus.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.URLhaus.category | string | | |
action_result.data.\*.attributes.last_analysis_results.URLhaus.method | string | | |
action_result.data.\*.attributes.last_analysis_results.URLhaus.result | string | | |
action_result.data.\*.attributes.last_analysis_results.URLQuery.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.URLQuery.category | string | | |
action_result.data.\*.attributes.last_analysis_results.URLQuery.method | string | | |
action_result.data.\*.attributes.last_analysis_results.URLQuery.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Viettel_Threat_Intelligence.result | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.category | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.method | string | | |
action_result.data.\*.attributes.last_analysis_results.VIPRE.result | string | | |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.category | string | | |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.method | string | | |
action_result.data.\*.attributes.last_analysis_results.VX_Vault.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ViriBack.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ViriBack.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ViriBack.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ViriBack.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Webroot.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Yandex_Safebrowsing.result | string | | |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.category | string | | |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.method | string | | |
action_result.data.\*.attributes.last_analysis_results.ZeroCERT.result | string | | |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.category | string | | |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.method | string | | |
action_result.data.\*.attributes.last_analysis_results.desenmascara_me.result | string | | |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.category | string | | |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.method | string | | |
action_result.data.\*.attributes.last_analysis_results.malwares_com_URL_checker.result | string | | |
action_result.data.\*.attributes.last_analysis_results.securolytics.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.securolytics.category | string | | |
action_result.data.\*.attributes.last_analysis_results.securolytics.method | string | | |
action_result.data.\*.attributes.last_analysis_results.securolytics.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Xcitium_Verdict_Cloud.result | string | | |
action_result.data.\*.attributes.last_analysis_results.zvelo.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.zvelo.category | string | | |
action_result.data.\*.attributes.last_analysis_results.zvelo.method | string | | |
action_result.data.\*.attributes.last_analysis_results.zvelo.result | string | | |
action_result.data.\*.attributes.last_analysis_results.Zerofox.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.Zerofox.category | string | | |
action_result.data.\*.attributes.last_analysis_results.Zerofox.method | string | | |
action_result.data.\*.attributes.last_analysis_results.Zerofox.result | string | | |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature | string | | |
action_result.data.\*.attributes.last_https_certificate.cert_signature.signature_algorithm | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.authority_key_identifier.keyid | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_key_identifier | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.subject_alternative_name.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.certificate_policies.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.key_usage.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.extended_key_usage.\* | string | | |
action_result.data.\*.attributes.last_https_certificate.extensions.crl_distribution_points.\* | string | `url` | |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.CA_Issuers | string | `url` | |
action_result.data.\*.attributes.last_https_certificate.extensions.ca_information_access.OCSP | string | `url` | |
action_result.data.\*.attributes.last_https_certificate.extensions.CA | boolean | | True False |
action_result.data.\*.attributes.last_https_certificate.extensions.1_3_6_1_4_1_11129_2_4_2 | string | | |
action_result.data.\*.attributes.last_https_certificate.validity.not_before | string | `date` | |
action_result.data.\*.attributes.last_https_certificate.validity.not_after | string | `date` | |
action_result.data.\*.attributes.last_https_certificate.size | numeric | | |
action_result.data.\*.attributes.last_https_certificate.version | string | | |
action_result.data.\*.attributes.last_https_certificate.public_key.algorithm | string | | |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.exponent | string | | |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.key_size | numeric | | |
action_result.data.\*.attributes.last_https_certificate.public_key.rsa.modulus | string | | |
action_result.data.\*.attributes.last_https_certificate.thumbprint_sha256 | string | | |
action_result.data.\*.attributes.last_https_certificate.thumbprint | string | | |
action_result.data.\*.attributes.last_https_certificate.serial_number | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.CN | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.O | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.C | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.L | string | | |
action_result.data.\*.attributes.last_https_certificate.issuer.ST | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.CN | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.O | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.C | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.L | string | | |
action_result.data.\*.attributes.last_https_certificate.subject.ST | string | | |
action_result.data.\*.attributes.last_https_certificate_date | numeric | `timestamp` | |
action_result.data.\*.attributes.last_modification_date | numeric | `timestamp` | |
action_result.data.\*.attributes.reputation | numeric | | |
action_result.data.\*.attributes.total_votes.harmless | numeric | | |
action_result.data.\*.attributes.total_votes.malicious | numeric | | |
action_result.data.\*.attributes.whois | string | | |
action_result.data.\*.attributes.whois_date | numeric | `timestamp` | |
action_result.data.\*.attributes.tags.\* | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'url reputation'

Queries VirusTotal for URL info (run this action after running detonate url)

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` | |
action_result.data.\*.attributes.categories.alphaMountain_ai | string | | |
action_result.data.\*.attributes.categories.BitDefender | string | | |
action_result.data.\*.attributes.categories.Xcitium_Verdict_Cloud | string | | |
action_result.data.\*.attributes.categories.Sophos | string | | |
action_result.data.\*.attributes.categories.Forcepoint_ThreatSeeker | string | | |
action_result.data.\*.attributes.favicon.dhash | string | | |
action_result.data.\*.attributes.favicon.raw_md5 | string | `md5` | |
action_result.data.\*.attributes.first_submission_date | string | `timestamp` | |
action_result.data.\*.attributes.last_analysis_date | string | `timestamp` | |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | AutoShun, CMC |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | |
action_result.data.\*.attributes.last_final_url | string | | |
action_result.data.\*.attributes.last_http_response_code | numeric | | |
action_result.data.\*.attributes.last_http_response_content_length | numeric | | |
action_result.data.\*.attributes.last_http_response_content_sha256 | string | `sha256` | |
action_result.data.\*.attributes.last_modification_date | string | `timestamp` | |
action_result.data.\*.attributes.last_submission_date | string | `timestamp` | |
action_result.data.\*.attributes.outgoing_links.\* | string | | |
action_result.data.\*.attributes.redirection_chain.\* | string | | |
action_result.data.\*.attributes.reputation | numeric | | |
action_result.data.\*.attributes.tags.\* | string | | |
action_result.data.\*.attributes.times_submitted | numeric | | |
action_result.data.\*.attributes.title | string | | |
action_result.data.\*.attributes.total_votes.harmless | numeric | | |
action_result.data.\*.attributes.total_votes.malicious | numeric | | |
action_result.data.\*.attributes.url | string | `url` | |
action_result.data.\*.attributes.has_content | boolean | | True False |
action_result.data.\*.id | string | | 99999999eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.type | string | | url |
action_result.summary.scan_id | string | | |
action_result.summary.harmless | numeric | | |
action_result.summary.malicious | numeric | | |
action_result.summary.suspicious | numeric | | |
action_result.summary.timeout | numeric | | |
action_result.summary.undetected | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Load a URL to Virus Total and retrieve analysis results

Type: **investigate** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` | |
action_result.parameter.wait_time | numeric | | |
action_result.data.\*.attributes.categories.alphaMountain_ai | string | | |
action_result.data.\*.attributes.categories.BitDefender | string | | |
action_result.data.\*.attributes.categories.Xcitium_Verdict_Cloud | string | | |
action_result.data.\*.attributes.categories.Sophos | string | | |
action_result.data.\*.attributes.categories.Forcepoint_ThreatSeeker | string | | |
action_result.data.\*.attributes.favicon.dhash | string | | |
action_result.data.\*.attributes.favicon.raw_md5 | string | `md5` | |
action_result.data.\*.attributes.first_submission_date | string | `timestamp` | |
action_result.data.\*.attributes.last_analysis_date | string | `timestamp` | |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | malicious |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | CMC |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | blacklist |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | Trojan.GenericKD.3275421 |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | AutoShun, CMC |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | |
action_result.data.\*.attributes.last_final_url | string | | |
action_result.data.\*.attributes.last_http_response_code | numeric | | |
action_result.data.\*.attributes.last_http_response_content_length | numeric | | |
action_result.data.\*.attributes.last_http_response_content_sha256 | string | `sha256` | |
action_result.data.\*.attributes.last_modification_date | string | `timestamp` | |
action_result.data.\*.attributes.last_submission_date | string | `timestamp` | |
action_result.data.\*.attributes.outgoing_links.\* | string | | |
action_result.data.\*.attributes.redirection_chain.\* | string | | |
action_result.data.\*.attributes.reputation | numeric | | |
action_result.data.\*.attributes.tags.\* | string | | |
action_result.data.\*.attributes.times_submitted | numeric | | |
action_result.data.\*.attributes.title | string | | |
action_result.data.\*.attributes.total_votes.harmless | numeric | | |
action_result.data.\*.attributes.total_votes.malicious | numeric | | |
action_result.data.\*.attributes.url | string | `url` | |
action_result.data.\*.attributes.has_content | boolean | | True False |
action_result.data.\*.data.attributes.date | numeric | `timestamp` | 1613651763 |
action_result.data.\*.data.attributes.results.Bkav.category | string | | |
action_result.data.\*.data.attributes.results.Bkav.engine_name | string | | |
action_result.data.\*.data.attributes.results.Bkav.engine_version | string | | |
action_result.data.\*.data.attributes.results.Bkav.engine_update | string | | |
action_result.data.\*.data.attributes.results.Bkav.method | string | | |
action_result.data.\*.data.attributes.results.Bkav.result | string | | |
action_result.data.\*.data.attributes.results.Bkav.vendor | string | | |
action_result.data.\*.data.attributes.results.Lionic.category | string | | |
action_result.data.\*.data.attributes.results.Lionic.engine_name | string | | |
action_result.data.\*.data.attributes.results.Lionic.engine_version | string | | |
action_result.data.\*.data.attributes.results.Lionic.engine_update | string | | |
action_result.data.\*.data.attributes.results.Lionic.method | string | | |
action_result.data.\*.data.attributes.results.Lionic.result | string | | |
action_result.data.\*.data.attributes.results.Lionic.vendor | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.category | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.engine_name | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.engine_version | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.engine_update | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.method | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.result | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.vendor | string | | |
action_result.data.\*.data.attributes.results.ClamAV.category | string | | |
action_result.data.\*.data.attributes.results.ClamAV.engine_name | string | | |
action_result.data.\*.data.attributes.results.ClamAV.engine_version | string | | |
action_result.data.\*.data.attributes.results.ClamAV.engine_update | string | | |
action_result.data.\*.data.attributes.results.ClamAV.method | string | | |
action_result.data.\*.data.attributes.results.ClamAV.result | string | | |
action_result.data.\*.data.attributes.results.ClamAV.vendor | string | | |
action_result.data.\*.data.attributes.results.CTX.category | string | | |
action_result.data.\*.data.attributes.results.CTX.engine_name | string | | |
action_result.data.\*.data.attributes.results.CTX.engine_version | string | | |
action_result.data.\*.data.attributes.results.CTX.engine_update | string | | |
action_result.data.\*.data.attributes.results.CTX.method | string | | |
action_result.data.\*.data.attributes.results.CTX.result | string | | |
action_result.data.\*.data.attributes.results.CTX.vendor | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.category | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.engine_name | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.engine_version | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.engine_update | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.method | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.result | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.vendor | string | | |
action_result.data.\*.data.attributes.results.ALYac.category | string | | |
action_result.data.\*.data.attributes.results.ALYac.engine_name | string | | |
action_result.data.\*.data.attributes.results.ALYac.engine_version | string | | |
action_result.data.\*.data.attributes.results.ALYac.engine_update | string | | |
action_result.data.\*.data.attributes.results.ALYac.method | string | | |
action_result.data.\*.data.attributes.results.ALYac.result | string | | |
action_result.data.\*.data.attributes.results.ALYac.vendor | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.category | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_name | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_version | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_update | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.method | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.result | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.vendor | string | | |
action_result.data.\*.data.attributes.results.Zillya.category | string | | |
action_result.data.\*.data.attributes.results.Zillya.engine_name | string | | |
action_result.data.\*.data.attributes.results.Zillya.engine_version | string | | |
action_result.data.\*.data.attributes.results.Zillya.engine_update | string | | |
action_result.data.\*.data.attributes.results.Zillya.method | string | | |
action_result.data.\*.data.attributes.results.Zillya.result | string | | |
action_result.data.\*.data.attributes.results.Zillya.vendor | string | | |
action_result.data.\*.data.attributes.results.Sangfor.category | string | | |
action_result.data.\*.data.attributes.results.Sangfor.engine_name | string | | |
action_result.data.\*.data.attributes.results.Sangfor.engine_version | string | | |
action_result.data.\*.data.attributes.results.Sangfor.engine_update | string | | |
action_result.data.\*.data.attributes.results.Sangfor.method | string | | |
action_result.data.\*.data.attributes.results.Sangfor.result | string | | |
action_result.data.\*.data.attributes.results.Sangfor.vendor | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.category | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_name | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_version | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_update | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.method | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.result | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.vendor | string | | |
action_result.data.\*.data.attributes.results.K7GW.category | string | | |
action_result.data.\*.data.attributes.results.K7GW.engine_name | string | | |
action_result.data.\*.data.attributes.results.K7GW.engine_version | string | | |
action_result.data.\*.data.attributes.results.K7GW.engine_update | string | | |
action_result.data.\*.data.attributes.results.K7GW.method | string | | |
action_result.data.\*.data.attributes.results.K7GW.result | string | | |
action_result.data.\*.data.attributes.results.K7GW.vendor | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.category | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_name | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_version | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_update | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.method | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.result | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.vendor | string | | |
action_result.data.\*.data.attributes.results.Baidu.category | string | | |
action_result.data.\*.data.attributes.results.Baidu.engine_name | string | | |
action_result.data.\*.data.attributes.results.Baidu.engine_version | string | | |
action_result.data.\*.data.attributes.results.Baidu.engine_update | string | | |
action_result.data.\*.data.attributes.results.Baidu.method | string | | |
action_result.data.\*.data.attributes.results.Baidu.result | string | | |
action_result.data.\*.data.attributes.results.Baidu.vendor | string | | |
action_result.data.\*.data.attributes.results.Symantec.category | string | | |
action_result.data.\*.data.attributes.results.Symantec.engine_name | string | | |
action_result.data.\*.data.attributes.results.Symantec.engine_version | string | | |
action_result.data.\*.data.attributes.results.Symantec.engine_update | string | | |
action_result.data.\*.data.attributes.results.Symantec.method | string | | |
action_result.data.\*.data.attributes.results.Symantec.result | string | | |
action_result.data.\*.data.attributes.results.Symantec.vendor | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.category | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.engine_name | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.engine_version | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.engine_update | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.method | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.result | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.vendor | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.category | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.engine_name | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.engine_version | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.engine_update | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.method | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.result | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.vendor | string | | |
action_result.data.\*.data.attributes.results.Avast.category | string | | |
action_result.data.\*.data.attributes.results.Avast.engine_name | string | | |
action_result.data.\*.data.attributes.results.Avast.engine_version | string | | |
action_result.data.\*.data.attributes.results.Avast.engine_update | string | | |
action_result.data.\*.data.attributes.results.Avast.method | string | | |
action_result.data.\*.data.attributes.results.Avast.result | string | | |
action_result.data.\*.data.attributes.results.Avast.vendor | string | | |
action_result.data.\*.data.attributes.results.Cynet.category | string | | |
action_result.data.\*.data.attributes.results.Cynet.engine_name | string | | |
action_result.data.\*.data.attributes.results.Cynet.engine_version | string | | |
action_result.data.\*.data.attributes.results.Cynet.engine_update | string | | |
action_result.data.\*.data.attributes.results.Cynet.method | string | | |
action_result.data.\*.data.attributes.results.Cynet.result | string | | |
action_result.data.\*.data.attributes.results.Cynet.vendor | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.category | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.engine_name | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.engine_version | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.engine_update | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.method | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.result | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.vendor | string | | |
action_result.data.\*.data.attributes.results.BitDefender.category | string | | |
action_result.data.\*.data.attributes.results.BitDefender.engine_name | string | | |
action_result.data.\*.data.attributes.results.BitDefender.engine_version | string | | |
action_result.data.\*.data.attributes.results.BitDefender.engine_update | string | | |
action_result.data.\*.data.attributes.results.BitDefender.method | string | | |
action_result.data.\*.data.attributes.results.BitDefender.result | string | | |
action_result.data.\*.data.attributes.results.BitDefender.vendor | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.category | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.engine_name | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.engine_version | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.engine_update | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.method | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.result | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.vendor | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.category | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_name | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_version | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_update | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.method | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.result | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.vendor | string | | |
action_result.data.\*.data.attributes.results.Rising.category | string | | |
action_result.data.\*.data.attributes.results.Rising.engine_name | string | | |
action_result.data.\*.data.attributes.results.Rising.engine_version | string | | |
action_result.data.\*.data.attributes.results.Rising.engine_update | string | | |
action_result.data.\*.data.attributes.results.Rising.method | string | | |
action_result.data.\*.data.attributes.results.Rising.result | string | | |
action_result.data.\*.data.attributes.results.Rising.vendor | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.category | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.method | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.result | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.vendor | string | | |
action_result.data.\*.data.attributes.results.F_Secure.category | string | | |
action_result.data.\*.data.attributes.results.F_Secure.engine_name | string | | |
action_result.data.\*.data.attributes.results.F_Secure.engine_version | string | | |
action_result.data.\*.data.attributes.results.F_Secure.engine_update | string | | |
action_result.data.\*.data.attributes.results.F_Secure.method | string | | |
action_result.data.\*.data.attributes.results.F_Secure.result | string | | |
action_result.data.\*.data.attributes.results.F_Secure.vendor | string | | |
action_result.data.\*.data.attributes.results.DrWeb.category | string | | |
action_result.data.\*.data.attributes.results.DrWeb.engine_name | string | | |
action_result.data.\*.data.attributes.results.DrWeb.engine_version | string | | |
action_result.data.\*.data.attributes.results.DrWeb.engine_update | string | | |
action_result.data.\*.data.attributes.results.DrWeb.method | string | | |
action_result.data.\*.data.attributes.results.DrWeb.result | string | | |
action_result.data.\*.data.attributes.results.DrWeb.vendor | string | | |
action_result.data.\*.data.attributes.results.VIPRE.category | string | | |
action_result.data.\*.data.attributes.results.VIPRE.engine_name | string | | |
action_result.data.\*.data.attributes.results.VIPRE.engine_version | string | | |
action_result.data.\*.data.attributes.results.VIPRE.engine_update | string | | |
action_result.data.\*.data.attributes.results.VIPRE.method | string | | |
action_result.data.\*.data.attributes.results.VIPRE.result | string | | |
action_result.data.\*.data.attributes.results.VIPRE.vendor | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.category | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.engine_name | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.engine_version | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.engine_update | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.method | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.result | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.vendor | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.category | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.engine_name | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.engine_version | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.engine_update | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.method | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.result | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.vendor | string | | |
action_result.data.\*.data.attributes.results.CMC.category | string | | |
action_result.data.\*.data.attributes.results.CMC.engine_name | string | | |
action_result.data.\*.data.attributes.results.CMC.engine_version | string | | |
action_result.data.\*.data.attributes.results.CMC.engine_update | string | | |
action_result.data.\*.data.attributes.results.CMC.method | string | | |
action_result.data.\*.data.attributes.results.CMC.result | string | | |
action_result.data.\*.data.attributes.results.CMC.vendor | string | | |
action_result.data.\*.data.attributes.results.Sophos.category | string | | |
action_result.data.\*.data.attributes.results.Sophos.engine_name | string | | |
action_result.data.\*.data.attributes.results.Sophos.engine_version | string | | |
action_result.data.\*.data.attributes.results.Sophos.engine_update | string | | |
action_result.data.\*.data.attributes.results.Sophos.method | string | | |
action_result.data.\*.data.attributes.results.Sophos.result | string | | |
action_result.data.\*.data.attributes.results.Sophos.vendor | string | | |
action_result.data.\*.data.attributes.results.Ikarus.category | string | | |
action_result.data.\*.data.attributes.results.Ikarus.engine_name | string | | |
action_result.data.\*.data.attributes.results.Ikarus.engine_version | string | | |
action_result.data.\*.data.attributes.results.Ikarus.engine_update | string | | |
action_result.data.\*.data.attributes.results.Ikarus.method | string | | |
action_result.data.\*.data.attributes.results.Ikarus.result | string | | |
action_result.data.\*.data.attributes.results.Ikarus.vendor | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.category | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.engine_name | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.engine_version | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.engine_update | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.method | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.result | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.vendor | string | | |
action_result.data.\*.data.attributes.results.Google.category | string | | |
action_result.data.\*.data.attributes.results.Google.engine_name | string | | |
action_result.data.\*.data.attributes.results.Google.engine_version | string | | |
action_result.data.\*.data.attributes.results.Google.engine_update | string | | |
action_result.data.\*.data.attributes.results.Google.method | string | | |
action_result.data.\*.data.attributes.results.Google.result | string | | |
action_result.data.\*.data.attributes.results.Google.vendor | string | | |
action_result.data.\*.data.attributes.results.Avira.category | string | | |
action_result.data.\*.data.attributes.results.Avira.engine_name | string | | |
action_result.data.\*.data.attributes.results.Avira.engine_version | string | | |
action_result.data.\*.data.attributes.results.Avira.engine_update | string | | |
action_result.data.\*.data.attributes.results.Avira.method | string | | |
action_result.data.\*.data.attributes.results.Avira.result | string | | |
action_result.data.\*.data.attributes.results.Avira.vendor | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.category | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.engine_name | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.engine_version | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.engine_update | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.method | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.result | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.vendor | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.category | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.method | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.result | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.vendor | string | | |
action_result.data.\*.data.attributes.results.Microsoft.category | string | | |
action_result.data.\*.data.attributes.results.Microsoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Microsoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Microsoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Microsoft.method | string | | |
action_result.data.\*.data.attributes.results.Microsoft.result | string | | |
action_result.data.\*.data.attributes.results.Microsoft.vendor | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.category | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.method | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.result | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.vendor | string | | |
action_result.data.\*.data.attributes.results.Xcitium.category | string | | |
action_result.data.\*.data.attributes.results.Xcitium.engine_name | string | | |
action_result.data.\*.data.attributes.results.Xcitium.engine_version | string | | |
action_result.data.\*.data.attributes.results.Xcitium.engine_update | string | | |
action_result.data.\*.data.attributes.results.Xcitium.method | string | | |
action_result.data.\*.data.attributes.results.Xcitium.result | string | | |
action_result.data.\*.data.attributes.results.Xcitium.vendor | string | | |
action_result.data.\*.data.attributes.results.Acrabit.category | string | | |
action_result.data.\*.data.attributes.results.Acrabit.engine_name | string | | |
action_result.data.\*.data.attributes.results.Acrabit.engine_version | string | | |
action_result.data.\*.data.attributes.results.Acrabit.engine_update | string | | |
action_result.data.\*.data.attributes.results.Acrabit.method | string | | |
action_result.data.\*.data.attributes.results.Acrabit.result | string | | |
action_result.data.\*.data.attributes.results.Acrabit.vendor | string | | |
action_result.data.\*.data.attributes.results.ViRobot.category | string | | |
action_result.data.\*.data.attributes.results.ViRobot.engine_name | string | | |
action_result.data.\*.data.attributes.results.ViRobot.engine_version | string | | |
action_result.data.\*.data.attributes.results.ViRobot.engine_update | string | | |
action_result.data.\*.data.attributes.results.ViRobot.method | string | | |
action_result.data.\*.data.attributes.results.ViRobot.result | string | | |
action_result.data.\*.data.attributes.results.ViRobot.vendor | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.category | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_name | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_version | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_update | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.method | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.result | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.vendor | string | | |
action_result.data.\*.data.attributes.results.GData.category | string | | |
action_result.data.\*.data.attributes.results.GData.engine_name | string | | |
action_result.data.\*.data.attributes.results.GData.engine_version | string | | |
action_result.data.\*.data.attributes.results.GData.engine_update | string | | |
action_result.data.\*.data.attributes.results.GData.method | string | | |
action_result.data.\*.data.attributes.results.GData.result | string | | |
action_result.data.\*.data.attributes.results.GData.vendor | string | | |
action_result.data.\*.data.attributes.results.Varist.category | string | | |
action_result.data.\*.data.attributes.results.Varist.engine_name | string | | |
action_result.data.\*.data.attributes.results.Varist.engine_version | string | | |
action_result.data.\*.data.attributes.results.Varist.engine_update | string | | |
action_result.data.\*.data.attributes.results.Varist.method | string | | |
action_result.data.\*.data.attributes.results.Varist.result | string | | |
action_result.data.\*.data.attributes.results.Varist.vendor | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.category | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.engine_name | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.engine_version | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.engine_update | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.method | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.result | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.vendor | string | | |
action_result.data.\*.data.attributes.results.Acronis.category | string | | |
action_result.data.\*.data.attributes.results.Acronis.engine_name | string | | |
action_result.data.\*.data.attributes.results.Acronis.engine_version | string | | |
action_result.data.\*.data.attributes.results.Acronis.engine_update | string | | |
action_result.data.\*.data.attributes.results.Acronis.method | string | | |
action_result.data.\*.data.attributes.results.Acronis.result | string | | |
action_result.data.\*.data.attributes.results.Acronis.vendor | string | | |
action_result.data.\*.data.attributes.results.VBA32.category | string | | |
action_result.data.\*.data.attributes.results.VBA32.engine_name | string | | |
action_result.data.\*.data.attributes.results.VBA32.engine_version | string | | |
action_result.data.\*.data.attributes.results.VBA32.engine_update | string | | |
action_result.data.\*.data.attributes.results.VBA32.method | string | | |
action_result.data.\*.data.attributes.results.VBA32.result | string | | |
action_result.data.\*.data.attributes.results.VBA32.vendor | string | | |
action_result.data.\*.data.attributes.results.TACHYON.category | string | | |
action_result.data.\*.data.attributes.results.TACHYON.engine_name | string | | |
action_result.data.\*.data.attributes.results.TACHYON.engine_version | string | | |
action_result.data.\*.data.attributes.results.TACHYON.engine_update | string | | |
action_result.data.\*.data.attributes.results.TACHYON.method | string | | |
action_result.data.\*.data.attributes.results.TACHYON.result | string | | |
action_result.data.\*.data.attributes.results.TACHYON.vendor | string | | |
action_result.data.\*.data.attributes.results.Zoner.category | string | | |
action_result.data.\*.data.attributes.results.Zoner.engine_name | string | | |
action_result.data.\*.data.attributes.results.Zoner.engine_version | string | | |
action_result.data.\*.data.attributes.results.Zoner.engine_update | string | | |
action_result.data.\*.data.attributes.results.Zoner.method | string | | |
action_result.data.\*.data.attributes.results.Zoner.result | string | | |
action_result.data.\*.data.attributes.results.Zoner.vendor | string | | |
action_result.data.\*.data.attributes.results.Tencent.category | string | | |
action_result.data.\*.data.attributes.results.Tencent.engine_name | string | | |
action_result.data.\*.data.attributes.results.Tencent.engine_version | string | | |
action_result.data.\*.data.attributes.results.Tencent.engine_update | string | | |
action_result.data.\*.data.attributes.results.Tencent.method | string | | |
action_result.data.\*.data.attributes.results.Tencent.result | string | | |
action_result.data.\*.data.attributes.results.Tencent.vendor | string | | |
action_result.data.\*.data.attributes.results.Yandex.category | string | | |
action_result.data.\*.data.attributes.results.Yandex.engine_name | string | | |
action_result.data.\*.data.attributes.results.Yandex.engine_version | string | | |
action_result.data.\*.data.attributes.results.Yandex.engine_update | string | | |
action_result.data.\*.data.attributes.results.Yandex.method | string | | |
action_result.data.\*.data.attributes.results.Yandex.result | string | | |
action_result.data.\*.data.attributes.results.Yandex.vendor | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.category | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.engine_name | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.engine_version | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.engine_update | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.method | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.result | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.vendor | string | | |
action_result.data.\*.data.attributes.results.huorong.category | string | | |
action_result.data.\*.data.attributes.results.huorong.engine_name | string | | |
action_result.data.\*.data.attributes.results.huorong.engine_version | string | | |
action_result.data.\*.data.attributes.results.huorong.engine_update | string | | |
action_result.data.\*.data.attributes.results.huorong.method | string | | |
action_result.data.\*.data.attributes.results.huorong.result | string | | |
action_result.data.\*.data.attributes.results.huorong.vendor | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.category | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.engine_name | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.engine_version | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.engine_update | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.method | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.result | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.vendor | string | | |
action_result.data.\*.data.attributes.results.Fortinet.category | string | | |
action_result.data.\*.data.attributes.results.Fortinet.engine_name | string | | |
action_result.data.\*.data.attributes.results.Fortinet.engine_version | string | | |
action_result.data.\*.data.attributes.results.Fortinet.engine_update | string | | |
action_result.data.\*.data.attributes.results.Fortinet.method | string | | |
action_result.data.\*.data.attributes.results.Fortinet.result | string | | |
action_result.data.\*.data.attributes.results.Fortinet.vendor | string | | |
action_result.data.\*.data.attributes.results.AVG.category | string | | |
action_result.data.\*.data.attributes.results.AVG.engine_name | string | | |
action_result.data.\*.data.attributes.results.AVG.engine_version | string | | |
action_result.data.\*.data.attributes.results.AVG.engine_update | string | | |
action_result.data.\*.data.attributes.results.AVG.method | string | | |
action_result.data.\*.data.attributes.results.AVG.result | string | | |
action_result.data.\*.data.attributes.results.AVG.vendor | string | | |
action_result.data.\*.data.attributes.results.Panda.category | string | | |
action_result.data.\*.data.attributes.results.Panda.engine_name | string | | |
action_result.data.\*.data.attributes.results.Panda.engine_version | string | | |
action_result.data.\*.data.attributes.results.Panda.engine_update | string | | |
action_result.data.\*.data.attributes.results.Panda.method | string | | |
action_result.data.\*.data.attributes.results.Panda.result | string | | |
action_result.data.\*.data.attributes.results.Panda.vendor | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.category | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.engine_name | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.engine_version | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.engine_update | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.method | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.result | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.vendor | string | | |
action_result.data.\*.data.attributes.results.VirIT.category | string | | |
action_result.data.\*.data.attributes.results.VirIT.engine_name | string | | |
action_result.data.\*.data.attributes.results.VirIT.engine_version | string | | |
action_result.data.\*.data.attributes.results.VirIT.engine_update | string | | |
action_result.data.\*.data.attributes.results.VirIT.method | string | | |
action_result.data.\*.data.attributes.results.VirIT.result | string | | |
action_result.data.\*.data.attributes.results.VirIT.vendor | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.category | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.engine_name | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.engine_version | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.engine_update | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.method | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.result | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.vendor | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.category | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.engine_name | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.engine_version | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.engine_update | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.method | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.result | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.vendor | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.category | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_name | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_version | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_update | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.method | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.result | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.vendor | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.category | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_name | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_version | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_update | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.method | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.result | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.vendor | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.category | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.engine_name | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.engine_version | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.engine_update | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.method | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.result | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.vendor | string | | |
action_result.data.\*.data.attributes.results.Elastic.category | string | | |
action_result.data.\*.data.attributes.results.Elastic.engine_name | string | | |
action_result.data.\*.data.attributes.results.Elastic.engine_version | string | | |
action_result.data.\*.data.attributes.results.Elastic.engine_update | string | | |
action_result.data.\*.data.attributes.results.Elastic.method | string | | |
action_result.data.\*.data.attributes.results.Elastic.result | string | | |
action_result.data.\*.data.attributes.results.Elastic.vendor | string | | |
action_result.data.\*.data.attributes.results.APEX.category | string | | |
action_result.data.\*.data.attributes.results.APEX.engine_name | string | | |
action_result.data.\*.data.attributes.results.APEX.engine_version | string | | |
action_result.data.\*.data.attributes.results.APEX.engine_update | string | | |
action_result.data.\*.data.attributes.results.APEX.method | string | | |
action_result.data.\*.data.attributes.results.APEX.result | string | | |
action_result.data.\*.data.attributes.results.APEX.vendor | string | | |
action_result.data.\*.data.attributes.results.Paloalto.category | string | | |
action_result.data.\*.data.attributes.results.Paloalto.engine_name | string | | |
action_result.data.\*.data.attributes.results.Paloalto.engine_version | string | | |
action_result.data.\*.data.attributes.results.Paloalto.engine_update | string | | |
action_result.data.\*.data.attributes.results.Paloalto.method | string | | |
action_result.data.\*.data.attributes.results.Paloalto.result | string | | |
action_result.data.\*.data.attributes.results.Paloalto.vendor | string | | |
action_result.data.\*.data.attributes.results.Trapmine.category | string | | |
action_result.data.\*.data.attributes.results.Trapmine.engine_name | string | | |
action_result.data.\*.data.attributes.results.Trapmine.engine_version | string | | |
action_result.data.\*.data.attributes.results.Trapmine.engine_update | string | | |
action_result.data.\*.data.attributes.results.Trapmine.method | string | | |
action_result.data.\*.data.attributes.results.Trapmine.result | string | | |
action_result.data.\*.data.attributes.results.Trapmine.vendor | string | | |
action_result.data.\*.data.attributes.results.Alibaba.category | string | | |
action_result.data.\*.data.attributes.results.Alibaba.engine_name | string | | |
action_result.data.\*.data.attributes.results.Alibaba.engine_version | string | | |
action_result.data.\*.data.attributes.results.Alibaba.engine_update | string | | |
action_result.data.\*.data.attributes.results.Alibaba.method | string | | |
action_result.data.\*.data.attributes.results.Alibaba.result | string | | |
action_result.data.\*.data.attributes.results.Alibaba.vendor | string | | |
action_result.data.\*.data.attributes.results.Webroot.category | string | | |
action_result.data.\*.data.attributes.results.Webroot.engine_name | string | | |
action_result.data.\*.data.attributes.results.Webroot.engine_version | string | | |
action_result.data.\*.data.attributes.results.Webroot.engine_update | string | | |
action_result.data.\*.data.attributes.results.Webroot.method | string | | |
action_result.data.\*.data.attributes.results.Webroot.result | string | | |
action_result.data.\*.data.attributes.results.Webroot.vendor | string | | |
action_result.data.\*.data.attributes.results.Cylance.category | string | | |
action_result.data.\*.data.attributes.results.Cylance.engine_name | string | | |
action_result.data.\*.data.attributes.results.Cylance.engine_version | string | | |
action_result.data.\*.data.attributes.results.Cylance.engine_update | string | | |
action_result.data.\*.data.attributes.results.Cylance.method | string | | |
action_result.data.\*.data.attributes.results.Cylance.result | string | | |
action_result.data.\*.data.attributes.results.Cylance.vendor | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.category | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.engine_name | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.engine_version | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.engine_update | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.method | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.result | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.vendor | string | | |
action_result.data.\*.data.attributes.results.tehtris.category | string | | |
action_result.data.\*.data.attributes.results.tehtris.engine_name | string | | |
action_result.data.\*.data.attributes.results.tehtris.engine_version | string | | |
action_result.data.\*.data.attributes.results.tehtris.engine_update | string | | |
action_result.data.\*.data.attributes.results.tehtris.method | string | | |
action_result.data.\*.data.attributes.results.tehtris.result | string | | |
action_result.data.\*.data.attributes.results.tehtris.vendor | string | | |
action_result.data.\*.data.attributes.results.Trustlook.category | string | | |
action_result.data.\*.data.attributes.results.Trustlook.engine_name | string | | |
action_result.data.\*.data.attributes.results.Trustlook.engine_version | string | | |
action_result.data.\*.data.attributes.results.Trustlook.engine_update | string | | |
action_result.data.\*.data.attributes.results.Trustlook.method | string | | |
action_result.data.\*.data.attributes.results.Trustlook.result | string | | |
action_result.data.\*.data.attributes.results.Trustlook.vendor | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.category | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.engine_name | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.engine_version | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.engine_update | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.method | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.result | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.vendor | string | | |
action_result.data.\*.data.attributes.results.Nucleon.category | string | | |
action_result.data.\*.data.attributes.results.Nucleon.engine_name | string | | |
action_result.data.\*.data.attributes.results.Nucleon.engine_version | string | | |
action_result.data.\*.data.attributes.results.Nucleon.engine_update | string | | |
action_result.data.\*.data.attributes.results.Nucleon.method | string | | |
action_result.data.\*.data.attributes.results.Nucleon.result | string | | |
action_result.data.\*.data.attributes.results.Nucleon.vendor | string | | |
action_result.data.\*.data.attributes.stats.malicious | numeric | | |
action_result.data.\*.data.attributes.stats.suspicious | numeric | | |
action_result.data.\*.data.attributes.stats.undetected | numeric | | |
action_result.data.\*.data.attributes.stats.harmless | numeric | | |
action_result.data.\*.data.attributes.stats.timeout | numeric | | |
action_result.data.\*.data.attributes.stats.confirmed_timeout | numeric | | |
action_result.data.\*.data.attributes.stats.failure | numeric | | |
action_result.data.\*.data.attributes.stats.type_unsupported | numeric | | |
action_result.data.\*.data.attributes.status | string | | completed |
action_result.data.\*.data.id | string | `virustotal scan id` | MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw== |
action_result.data.\*.data.links.item | string | | https://www.virustotal.com/api/v3/files/917c72a2684d1573ea363b2f91e3aedcef1996fc34668ba9d369ad9123d1380f |
action_result.data.\*.data.links.self | string | | https://www.virustotal.com/api/v3/analyses/ZDhhNjY5NmU2NDJlYzUyMDUwMmEwNWE0YWRkOGMxNzk6MTY3ODY4OTQ5Mg== |
action_result.data.\*.data.type | string | | |
action_result.data.\*.data.meta.file_info.md5 | string | `md5` | 299999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.data.meta.file_info.name | string | | update_cr.py |
action_result.data.\*.data.meta.file_info.sha1 | string | `sha1` | 9999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.data.meta.file_info.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.data.meta.file_info.size | numeric | | 6285 |
action_result.data.\*.data.meta.url_info.id | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.data.meta.url_info.url | string | | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.id | string | | e0583d78eb4bea4078dce1d89e9eaabd7be7b6a8630f88b70a725c607cdce063 |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.meta.file_info.md5 | string | `md5` | 299999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.meta.file_info.name | string | | update_cr.py |
action_result.data.\*.meta.file_info.sha1 | string | `sha1` | 9999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.meta.file_info.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.file_info.size | numeric | | 6285 |
action_result.data.\*.meta.url_info.id | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.url_info.url | string | | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.type | string | | url |
action_result.data.\*.scan_id | string | | |
action_result.summary.scan_id | string | | |
action_result.summary.harmless | numeric | | |
action_result.summary.malicious | numeric | | |
action_result.summary.suspicious | numeric | | |
action_result.summary.timeout | numeric | | |
action_result.summary.undetected | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate file'

Upload a file to Virus Total and retrieve the analysis results

Type: **investigate** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` `sha1` | |
action_result.parameter.wait_time | numeric | | |
action_result.data.\*.vault_id | string | | |
action_result.data.\*.attributes.androguard.Activities.\* | string | | |
action_result.data.\*.attributes.androguard.AndroguardVersion | string | | 3.0-dev |
action_result.data.\*.attributes.androguard.AndroidApplication | numeric | | 1 |
action_result.data.\*.attributes.androguard.AndroidApplicationError | boolean | | True False |
action_result.data.\*.attributes.androguard.AndroidApplicationInfo | string | | APK |
action_result.data.\*.attributes.androguard.AndroidVersionCode | string | | 1 |
action_result.data.\*.attributes.androguard.AndroidVersionName | string | | 1.0 |
action_result.data.\*.attributes.androguard.MinSdkVersion | string | | 11 |
action_result.data.\*.attributes.androguard.Package | string | | com.ibm.android.analyzer.test |
action_result.data.\*.attributes.androguard.RiskIndicator.APK.\*.key | string | | ACTIVITY |
action_result.data.\*.attributes.androguard.RiskIndicator.APK.\*.value | numeric | | 5 |
action_result.data.\*.attributes.androguard.RiskIndicator.PERM.\*.key | string | | ACTIVITY |
action_result.data.\*.attributes.androguard.RiskIndicator.PERM.\*.value | numeric | | 5 |
action_result.data.\*.attributes.androguard.TargetSdkVersion | string | | 11 |
action_result.data.\*.attributes.androguard.VTAndroidInfo | numeric | | 1.41 |
action_result.data.\*.attributes.androguard.certificate.cert_signature.signature | string | | |
action_result.data.\*.attributes.androguard.certificate.cert_signature.signature_algorithm | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.authority_key_identifier.keyid | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.subject_key_identifier | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.subject_alternative_name.\* | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.certificate_policies.\* | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.key_usage.\* | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.extended_key_usage.\* | string | | |
action_result.data.\*.attributes.androguard.certificate.extensions.crl_distribution_points.\* | string | `url` | |
action_result.data.\*.attributes.androguard.certificate.extensions.ca_information_access.CA_Issuers | string | `url` | |
action_result.data.\*.attributes.androguard.certificate.extensions.ca_information_access.OCSP | string | `url` | |
action_result.data.\*.attributes.androguard.certificate.extensions.CA | boolean | | True False |
action_result.data.\*.attributes.androguard.certificate.extensions.1_3_6_1_4_1_11129_2_4_2 | string | | |
action_result.data.\*.attributes.androguard.certificate.validity.not_before | string | `date` | |
action_result.data.\*.attributes.androguard.certificate.validity.not_after | string | `date` | |
action_result.data.\*.attributes.androguard.certificate.size | numeric | | |
action_result.data.\*.attributes.androguard.certificate.version | string | | |
action_result.data.\*.attributes.androguard.certificate.public_key.algorithm | string | | |
action_result.data.\*.attributes.androguard.certificate.public_key.rsa.exponent | string | | |
action_result.data.\*.attributes.androguard.certificate.public_key.rsa.key_size | numeric | | |
action_result.data.\*.attributes.androguard.certificate.public_key.rsa.modulus | string | | |
action_result.data.\*.attributes.androguard.certificate.thumbprint_sha256 | string | | |
action_result.data.\*.attributes.androguard.certificate.thumbprint | string | | |
action_result.data.\*.attributes.androguard.certificate.serial_number | string | | |
action_result.data.\*.attributes.androguard.certificate.issuer.CN | string | | |
action_result.data.\*.attributes.androguard.certificate.issuer.O | string | | |
action_result.data.\*.attributes.androguard.certificate.issuer.C | string | | |
action_result.data.\*.attributes.androguard.certificate.issuer.L | string | | |
action_result.data.\*.attributes.androguard.certificate.issuer.ST | string | | |
action_result.data.\*.attributes.androguard.certificate.subject.CN | string | | |
action_result.data.\*.attributes.androguard.certificate.subject.O | string | | |
action_result.data.\*.attributes.androguard.certificate.subject.C | string | | |
action_result.data.\*.attributes.androguard.certificate.subject.L | string | | |
action_result.data.\*.attributes.androguard.certificate.subject.ST | string | | |
action_result.data.\*.attributes.androguard.main_activity | string | | com.ibm.android.analyzer.test.xas.CAS |
action_result.data.\*.attributes.androguard.Services.\* | string | | |
action_result.data.\*.attributes.androguard.StringsInformation.\* | string | | |
action_result.data.\*.attributes.androguard.permission_details.android.permission.INTERNET.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.INTERNET.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.INTERNET.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.WRITE_EXTERNAL_STORAGE.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.WRITE_EXTERNAL_STORAGE.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.WRITE_EXTERNAL_STORAGE.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_EXTERNAL_STORAGE.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_EXTERNAL_STORAGE.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_EXTERNAL_STORAGE.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_NETWORK_STATE.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_NETWORK_STATE.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_NETWORK_STATE.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.CAMERA.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.CAMERA.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.CAMERA.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.RECORD_AUDIO.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.RECORD_AUDIO.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.RECORD_AUDIO.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_FINE_LOCATION.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_FINE_LOCATION.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_FINE_LOCATION.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_COARSE_LOCATION.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_COARSE_LOCATION.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.ACCESS_COARSE_LOCATION.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_CONTACTS.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_CONTACTS.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_CONTACTS.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.WRITE_CONTACTS.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.WRITE_CONTACTS.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.WRITE_CONTACTS.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_SMS.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_SMS.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_SMS.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.SEND_SMS.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.SEND_SMS.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.SEND_SMS.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.CALL_PHONE.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.CALL_PHONE.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.CALL_PHONE.short_description | string | | full Internet access |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_PHONE_STATE.full_description | string | | Allows an application to create network sockets. |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_PHONE_STATE.permission_type | string | | dangerous |
action_result.data.\*.attributes.androguard.permission_details.android.permission.READ_PHONE_STATE.short_description | string | | full Internet access |
action_result.data.\*.attributes.authentihash | string | | 9999999999a601c12ac88d70736e5a5064dac716fe071ce9e3bb206d67b1b9a5 |
action_result.data.\*.attributes.bundle_info.extensions.\*.key | string | | .exe |
action_result.data.\*.attributes.bundle_info.extensions.\*.count | string | | 1 |
action_result.data.\*.attributes.bundle_info.file_types.\*.key | string | | .exe |
action_result.data.\*.attributes.bundle_info.file_types.\*.count | string | | 1 |
action_result.data.\*.attributes.bundle_info.highest_datetime | string | | 2019-01-03 12:33:40 |
action_result.data.\*.attributes.bundle_info.lowest_datetime | string | | 2019-01-03 12:33:40 |
action_result.data.\*.attributes.bundle_info.num_children | numeric | | 1 |
action_result.data.\*.attributes.bundle_info.type | string | | ZIP |
action_result.data.\*.attributes.bundle_info.uncompressed_size | numeric | | 481 |
action_result.data.\*.attributes.bytehero_info | string | | Trojan.Win32.Heur.Gen |
action_result.data.\*.attributes.creation_date | numeric | `timestamp` | 1539102614 |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.alert_severity | string | | medium |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_category | string | | Potentially Bad Traffic |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_id | string | | 1:2027865 |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_msg | string | | ET INFO Observed DNS Query to .cloud TLD |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_raw | string | | alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns.query; content:".cloud"; nocase; endswith; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027865; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2019_08_13, deployment Perimeter, former_category INFO, signature_severity Major, updated_at 2020_09_17;) |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_source | string | | Proofpoint Emerging Threats Open |
action_result.data.\*.attributes.crowdsourced_ids_results.\*.rule_url | string | | https://rules.emergingthreats.net/ |
action_result.data.\*.attributes.crowdsourced_ids_stats.\* | numeric | | 0 |
action_result.data.\*.attributes.first_seen_itw_date | numeric | `timestamp` | 1502111702 |
action_result.data.\*.attributes.first_submission_date | numeric | `timestamp` | 1612961082 |
action_result.data.\*.attributes.html_info.iframes.\*.attributes.src | string | | ./test_html_files/list.html |
action_result.data.\*.attributes.html_info.iframes.\*.attributes.width | string | | 100% |
action_result.data.\*.attributes.html_info.iframes.\*.attributes.height | string | | 400px |
action_result.data.\*.attributes.html_info.scripts.\*.attributes.src | string | | ./test_html_files/list.html |
action_result.data.\*.attributes.html_info.scripts.\*.attributes.width | string | | 100% |
action_result.data.\*.attributes.html_info.scripts.\*.attributes.height | string | | 400px |
action_result.data.\*.attributes.last_analysis_date | numeric | `timestamp` | 1613635130 |
action_result.data.\*.attributes.last_analysis_results.\*.category | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.engine_name | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.engine_version | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.engine_update | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.method | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.result | string | | |
action_result.data.\*.attributes.last_analysis_results.\*.vendor | string | | |
action_result.data.\*.attributes.last_analysis_stats.malicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.suspicious | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.undetected | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.harmless | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.confirmed_timeout | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.failure | numeric | | |
action_result.data.\*.attributes.last_analysis_stats.type_unsupported | numeric | | |
action_result.data.\*.attributes.last_modification_date | numeric | `timestamp` | 1613635210 |
action_result.data.\*.attributes.last_submission_date | numeric | `timestamp` | 1613635130 |
action_result.data.\*.attributes.magic | string | | a python2.7\\015script text executable |
action_result.data.\*.attributes.md5 | string | `md5` | 99999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.attributes.meaningful_name | string | | update_cr.py |
action_result.data.\*.attributes.names.\* | string | | ['update_cr.py'] |
action_result.data.\*.attributes.packers.F_PROT | string | | appended, docwrite |
action_result.data.\*.attributes.pdf_info.acroform | numeric | | |
action_result.data.\*.attributes.pdf_info.autoaction | numeric | | |
action_result.data.\*.attributes.pdf_info.embedded_file | numeric | | |
action_result.data.\*.attributes.pdf_info.encrypted | numeric | | |
action_result.data.\*.attributes.pdf_info.flash | numeric | | |
action_result.data.\*.attributes.pdf_info.header | string | | |
action_result.data.\*.attributes.pdf_info.javascript | numeric | | |
action_result.data.\*.attributes.pdf_info.jbig2_compression | numeric | | |
action_result.data.\*.attributes.pdf_info.js | numeric | | |
action_result.data.\*.attributes.pdf_info.num_endobj | numeric | | |
action_result.data.\*.attributes.pdf_info.num_endstream | numeric | | |
action_result.data.\*.attributes.pdf_info.num_launch_actions | numeric | | |
action_result.data.\*.attributes.pdf_info.num_obj | numeric | | |
action_result.data.\*.attributes.pdf_info.num_object_streams | numeric | | |
action_result.data.\*.attributes.pdf_info.num_pages | numeric | | |
action_result.data.\*.attributes.pdf_info.num_stream | numeric | | |
action_result.data.\*.attributes.pdf_info.openaction | numeric | | |
action_result.data.\*.attributes.pdf_info.startxref | numeric | | |
action_result.data.\*.attributes.pdf_info.suspicious_colors | numeric | | |
action_result.data.\*.attributes.pdf_info.trailer | numeric | | |
action_result.data.\*.attributes.pdf_info.xfa | numeric | | |
action_result.data.\*.attributes.pdf_info.xref | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.age | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.guid | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.name | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.offset | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.signature | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.codeview.timestamp | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.fpo.functions | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.datatype | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.length | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.unicode | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.data | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.misc.reserved | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.offset | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.reserved10.value | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.size | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.timestamp | string | | |
action_result.data.\*.attributes.pe_info.debug.\*.type | numeric | | |
action_result.data.\*.attributes.pe_info.debug.\*.type_str | string | | |
action_result.data.\*.attributes.pe_info.entry_point | numeric | | |
action_result.data.\*.attributes.pe_info.exports.\* | string | | |
action_result.data.\*.attributes.pe_info.imphash | string | | |
action_result.data.\*.attributes.pe_info.import_list.\*.imported_functions.\* | string | | |
action_result.data.\*.attributes.pe_info.import_list.\*.library_name | string | | |
action_result.data.\*.attributes.pe_info.machine_type | string | | |
action_result.data.\*.attributes.pe_info.overlay.chi2 | numeric | | |
action_result.data.\*.attributes.pe_info.overlay.entropy | numeric | | |
action_result.data.\*.attributes.pe_info.overlay.filetype | string | | |
action_result.data.\*.attributes.pe_info.overlay.md5 | string | `md5` | |
action_result.data.\*.attributes.pe_info.overlay.offset | numeric | | |
action_result.data.\*.attributes.pe_info.overlay.size | numeric | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.chi2 | numeric | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.entropy | numeric | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.filetype | string | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.lang | string | | |
action_result.data.\*.attributes.pe_info.resource_details.\*.sha256 | string | `sha256` | |
action_result.data.\*.attributes.pe_info.resource_details.\*.type | string | | |
action_result.data.\*.attributes.pe_info.sections.\*.entropy | numeric | | |
action_result.data.\*.attributes.pe_info.sections.\*.md5 | string | `md5` | |
action_result.data.\*.attributes.pe_info.sections.\*.name | string | | |
action_result.data.\*.attributes.pe_info.sections.\*.raw_size | numeric | | |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_address | numeric | | |
action_result.data.\*.attributes.pe_info.sections.\*.virtual_size | numeric | | |
action_result.data.\*.attributes.pe_info.timestamp | numeric | `timestamp` | |
action_result.data.\*.attributes.popular_threat_classification.suggested_threat_label | string | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.value | string | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_category.\*.count | numeric | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.value | string | | |
action_result.data.\*.attributes.popular_threat_classification.popular_threat_name.\*.count | numeric | | |
action_result.data.\*.attributes.reputation | numeric | | 0 |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.category | string | | malicious harmless suspicious |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.confidence | numeric | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.malware_classification.\* | string | | CLEAN |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.malware_names.\* | string | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox.sandbox_name | string | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.category | string | | malicious harmless suspicious |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.confidence | numeric | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.malware_classification.\* | string | | CLEAN |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.malware_names.\* | string | | |
action_result.data.\*.attributes.sandbox_verdicts.Zenbox_Linux.sandbox_name | string | | |
action_result.data.\*.attributes.sha1 | string | `sha1` | 99999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.attributes.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.attributes.signature_info.\* | string | | xyz |
action_result.data.\*.attributes.size | numeric | | 6285 |
action_result.data.\*.attributes.ssdeep | string | | 192:MPv2vv/ybXAhgPpyN3ipdw0fRAdygi6OLxgUHzYu7ThPBLkv:pq7Mgg0/NdMu/1BLkv |
action_result.data.\*.attributes.tags.\* | string | | ['python'] |
action_result.data.\*.attributes.times_submitted | numeric | | 13 |
action_result.data.\*.attributes.tlsh | string | | 9999999999C5E941C47329D1EDD16FD1BEB0122B724296327B46CA2997FB0468C3E14FC |
action_result.data.\*.attributes.total_votes.harmless | numeric | | |
action_result.data.\*.attributes.total_votes.malicious | numeric | | |
action_result.data.\*.attributes.trid.\*.file_type | string | | |
action_result.data.\*.attributes.trid.\*.probability | numeric | | |
action_result.data.\*.attributes.type_description | string | | Python |
action_result.data.\*.attributes.type_extension | string | | py |
action_result.data.\*.attributes.type_tag | string | | python |
action_result.data.\*.attributes.unique_sources | numeric | | 1 |
action_result.data.\*.attributes.vhash | string | | |
action_result.data.\*.data.attributes.date | numeric | `timestamp` | 1613651763 |
action_result.data.\*.data.attributes.results.Bkav.category | string | | |
action_result.data.\*.data.attributes.results.Bkav.engine_name | string | | |
action_result.data.\*.data.attributes.results.Bkav.engine_version | string | | |
action_result.data.\*.data.attributes.results.Bkav.engine_update | string | | |
action_result.data.\*.data.attributes.results.Bkav.method | string | | |
action_result.data.\*.data.attributes.results.Bkav.result | string | | |
action_result.data.\*.data.attributes.results.Bkav.vendor | string | | |
action_result.data.\*.data.attributes.results.Lionic.category | string | | |
action_result.data.\*.data.attributes.results.Lionic.engine_name | string | | |
action_result.data.\*.data.attributes.results.Lionic.engine_version | string | | |
action_result.data.\*.data.attributes.results.Lionic.engine_update | string | | |
action_result.data.\*.data.attributes.results.Lionic.method | string | | |
action_result.data.\*.data.attributes.results.Lionic.result | string | | |
action_result.data.\*.data.attributes.results.Lionic.vendor | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.category | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.engine_name | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.engine_version | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.engine_update | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.method | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.result | string | | |
action_result.data.\*.data.attributes.results.MicroWorld_eScan.vendor | string | | |
action_result.data.\*.data.attributes.results.ClamAV.category | string | | |
action_result.data.\*.data.attributes.results.ClamAV.engine_name | string | | |
action_result.data.\*.data.attributes.results.ClamAV.engine_version | string | | |
action_result.data.\*.data.attributes.results.ClamAV.engine_update | string | | |
action_result.data.\*.data.attributes.results.ClamAV.method | string | | |
action_result.data.\*.data.attributes.results.ClamAV.result | string | | |
action_result.data.\*.data.attributes.results.ClamAV.vendor | string | | |
action_result.data.\*.data.attributes.results.CTX.category | string | | |
action_result.data.\*.data.attributes.results.CTX.engine_name | string | | |
action_result.data.\*.data.attributes.results.CTX.engine_version | string | | |
action_result.data.\*.data.attributes.results.CTX.engine_update | string | | |
action_result.data.\*.data.attributes.results.CTX.method | string | | |
action_result.data.\*.data.attributes.results.CTX.result | string | | |
action_result.data.\*.data.attributes.results.CTX.vendor | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.category | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.engine_name | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.engine_version | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.engine_update | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.method | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.result | string | | |
action_result.data.\*.data.attributes.results.Skyhigh.vendor | string | | |
action_result.data.\*.data.attributes.results.ALYac.category | string | | |
action_result.data.\*.data.attributes.results.ALYac.engine_name | string | | |
action_result.data.\*.data.attributes.results.ALYac.engine_version | string | | |
action_result.data.\*.data.attributes.results.ALYac.engine_update | string | | |
action_result.data.\*.data.attributes.results.ALYac.method | string | | |
action_result.data.\*.data.attributes.results.ALYac.result | string | | |
action_result.data.\*.data.attributes.results.ALYac.vendor | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.category | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_name | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_version | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.engine_update | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.method | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.result | string | | |
action_result.data.\*.data.attributes.results.Malwarebytes.vendor | string | | |
action_result.data.\*.data.attributes.results.Zillya.category | string | | |
action_result.data.\*.data.attributes.results.Zillya.engine_name | string | | |
action_result.data.\*.data.attributes.results.Zillya.engine_version | string | | |
action_result.data.\*.data.attributes.results.Zillya.engine_update | string | | |
action_result.data.\*.data.attributes.results.Zillya.method | string | | |
action_result.data.\*.data.attributes.results.Zillya.result | string | | |
action_result.data.\*.data.attributes.results.Zillya.vendor | string | | |
action_result.data.\*.data.attributes.results.Sangfor.category | string | | |
action_result.data.\*.data.attributes.results.Sangfor.engine_name | string | | |
action_result.data.\*.data.attributes.results.Sangfor.engine_version | string | | |
action_result.data.\*.data.attributes.results.Sangfor.engine_update | string | | |
action_result.data.\*.data.attributes.results.Sangfor.method | string | | |
action_result.data.\*.data.attributes.results.Sangfor.result | string | | |
action_result.data.\*.data.attributes.results.Sangfor.vendor | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.category | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_name | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_version | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.engine_update | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.method | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.result | string | | |
action_result.data.\*.data.attributes.results.K7AntiVirus.vendor | string | | |
action_result.data.\*.data.attributes.results.K7GW.category | string | | |
action_result.data.\*.data.attributes.results.K7GW.engine_name | string | | |
action_result.data.\*.data.attributes.results.K7GW.engine_version | string | | |
action_result.data.\*.data.attributes.results.K7GW.engine_update | string | | |
action_result.data.\*.data.attributes.results.K7GW.method | string | | |
action_result.data.\*.data.attributes.results.K7GW.result | string | | |
action_result.data.\*.data.attributes.results.K7GW.vendor | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.category | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_name | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_version | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.engine_update | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.method | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.result | string | | |
action_result.data.\*.data.attributes.results.CrowdStrike.vendor | string | | |
action_result.data.\*.data.attributes.results.Baidu.category | string | | |
action_result.data.\*.data.attributes.results.Baidu.engine_name | string | | |
action_result.data.\*.data.attributes.results.Baidu.engine_version | string | | |
action_result.data.\*.data.attributes.results.Baidu.engine_update | string | | |
action_result.data.\*.data.attributes.results.Baidu.method | string | | |
action_result.data.\*.data.attributes.results.Baidu.result | string | | |
action_result.data.\*.data.attributes.results.Baidu.vendor | string | | |
action_result.data.\*.data.attributes.results.Symantec.category | string | | |
action_result.data.\*.data.attributes.results.Symantec.engine_name | string | | |
action_result.data.\*.data.attributes.results.Symantec.engine_version | string | | |
action_result.data.\*.data.attributes.results.Symantec.engine_update | string | | |
action_result.data.\*.data.attributes.results.Symantec.method | string | | |
action_result.data.\*.data.attributes.results.Symantec.result | string | | |
action_result.data.\*.data.attributes.results.Symantec.vendor | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.category | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.engine_name | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.engine_version | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.engine_update | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.method | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.result | string | | |
action_result.data.\*.data.attributes.results.ESET_NOD32.vendor | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.category | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.engine_name | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.engine_version | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.engine_update | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.method | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.result | string | | |
action_result.data.\*.data.attributes.results.TrendMicro_HouseCall.vendor | string | | |
action_result.data.\*.data.attributes.results.Avast.category | string | | |
action_result.data.\*.data.attributes.results.Avast.engine_name | string | | |
action_result.data.\*.data.attributes.results.Avast.engine_version | string | | |
action_result.data.\*.data.attributes.results.Avast.engine_update | string | | |
action_result.data.\*.data.attributes.results.Avast.method | string | | |
action_result.data.\*.data.attributes.results.Avast.result | string | | |
action_result.data.\*.data.attributes.results.Avast.vendor | string | | |
action_result.data.\*.data.attributes.results.Cynet.category | string | | |
action_result.data.\*.data.attributes.results.Cynet.engine_name | string | | |
action_result.data.\*.data.attributes.results.Cynet.engine_version | string | | |
action_result.data.\*.data.attributes.results.Cynet.engine_update | string | | |
action_result.data.\*.data.attributes.results.Cynet.method | string | | |
action_result.data.\*.data.attributes.results.Cynet.result | string | | |
action_result.data.\*.data.attributes.results.Cynet.vendor | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.category | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.engine_name | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.engine_version | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.engine_update | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.method | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.result | string | | |
action_result.data.\*.data.attributes.results.Kaspersky.vendor | string | | |
action_result.data.\*.data.attributes.results.BitDefender.category | string | | |
action_result.data.\*.data.attributes.results.BitDefender.engine_name | string | | |
action_result.data.\*.data.attributes.results.BitDefender.engine_version | string | | |
action_result.data.\*.data.attributes.results.BitDefender.engine_update | string | | |
action_result.data.\*.data.attributes.results.BitDefender.method | string | | |
action_result.data.\*.data.attributes.results.BitDefender.result | string | | |
action_result.data.\*.data.attributes.results.BitDefender.vendor | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.category | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.engine_name | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.engine_version | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.engine_update | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.method | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.result | string | | |
action_result.data.\*.data.attributes.results.NANO_Antivirus.vendor | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.category | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_name | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_version | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.engine_update | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.method | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.result | string | | |
action_result.data.\*.data.attributes.results.SUPERAntiSpyware.vendor | string | | |
action_result.data.\*.data.attributes.results.Rising.category | string | | |
action_result.data.\*.data.attributes.results.Rising.engine_name | string | | |
action_result.data.\*.data.attributes.results.Rising.engine_version | string | | |
action_result.data.\*.data.attributes.results.Rising.engine_update | string | | |
action_result.data.\*.data.attributes.results.Rising.method | string | | |
action_result.data.\*.data.attributes.results.Rising.result | string | | |
action_result.data.\*.data.attributes.results.Rising.vendor | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.category | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.method | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.result | string | | |
action_result.data.\*.data.attributes.results.Emsisoft.vendor | string | | |
action_result.data.\*.data.attributes.results.F_Secure.category | string | | |
action_result.data.\*.data.attributes.results.F_Secure.engine_name | string | | |
action_result.data.\*.data.attributes.results.F_Secure.engine_version | string | | |
action_result.data.\*.data.attributes.results.F_Secure.engine_update | string | | |
action_result.data.\*.data.attributes.results.F_Secure.method | string | | |
action_result.data.\*.data.attributes.results.F_Secure.result | string | | |
action_result.data.\*.data.attributes.results.F_Secure.vendor | string | | |
action_result.data.\*.data.attributes.results.DrWeb.category | string | | |
action_result.data.\*.data.attributes.results.DrWeb.engine_name | string | | |
action_result.data.\*.data.attributes.results.DrWeb.engine_version | string | | |
action_result.data.\*.data.attributes.results.DrWeb.engine_update | string | | |
action_result.data.\*.data.attributes.results.DrWeb.method | string | | |
action_result.data.\*.data.attributes.results.DrWeb.result | string | | |
action_result.data.\*.data.attributes.results.DrWeb.vendor | string | | |
action_result.data.\*.data.attributes.results.VIPRE.category | string | | |
action_result.data.\*.data.attributes.results.VIPRE.engine_name | string | | |
action_result.data.\*.data.attributes.results.VIPRE.engine_version | string | | |
action_result.data.\*.data.attributes.results.VIPRE.engine_update | string | | |
action_result.data.\*.data.attributes.results.VIPRE.method | string | | |
action_result.data.\*.data.attributes.results.VIPRE.result | string | | |
action_result.data.\*.data.attributes.results.VIPRE.vendor | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.category | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.engine_name | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.engine_version | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.engine_update | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.method | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.result | string | | |
action_result.data.\*.data.attributes.results.TrendMicro.vendor | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.category | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.engine_name | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.engine_version | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.engine_update | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.method | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.result | string | | |
action_result.data.\*.data.attributes.results.McAfeeD.vendor | string | | |
action_result.data.\*.data.attributes.results.CMC.category | string | | |
action_result.data.\*.data.attributes.results.CMC.engine_name | string | | |
action_result.data.\*.data.attributes.results.CMC.engine_version | string | | |
action_result.data.\*.data.attributes.results.CMC.engine_update | string | | |
action_result.data.\*.data.attributes.results.CMC.method | string | | |
action_result.data.\*.data.attributes.results.CMC.result | string | | |
action_result.data.\*.data.attributes.results.CMC.vendor | string | | |
action_result.data.\*.data.attributes.results.Sophos.category | string | | |
action_result.data.\*.data.attributes.results.Sophos.engine_name | string | | |
action_result.data.\*.data.attributes.results.Sophos.engine_version | string | | |
action_result.data.\*.data.attributes.results.Sophos.engine_update | string | | |
action_result.data.\*.data.attributes.results.Sophos.method | string | | |
action_result.data.\*.data.attributes.results.Sophos.result | string | | |
action_result.data.\*.data.attributes.results.Sophos.vendor | string | | |
action_result.data.\*.data.attributes.results.Ikarus.category | string | | |
action_result.data.\*.data.attributes.results.Ikarus.engine_name | string | | |
action_result.data.\*.data.attributes.results.Ikarus.engine_version | string | | |
action_result.data.\*.data.attributes.results.Ikarus.engine_update | string | | |
action_result.data.\*.data.attributes.results.Ikarus.method | string | | |
action_result.data.\*.data.attributes.results.Ikarus.result | string | | |
action_result.data.\*.data.attributes.results.Ikarus.vendor | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.category | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.engine_name | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.engine_version | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.engine_update | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.method | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.result | string | | |
action_result.data.\*.data.attributes.results.Jiangmin.vendor | string | | |
action_result.data.\*.data.attributes.results.Google.category | string | | |
action_result.data.\*.data.attributes.results.Google.engine_name | string | | |
action_result.data.\*.data.attributes.results.Google.engine_version | string | | |
action_result.data.\*.data.attributes.results.Google.engine_update | string | | |
action_result.data.\*.data.attributes.results.Google.method | string | | |
action_result.data.\*.data.attributes.results.Google.result | string | | |
action_result.data.\*.data.attributes.results.Google.vendor | string | | |
action_result.data.\*.data.attributes.results.Avira.category | string | | |
action_result.data.\*.data.attributes.results.Avira.engine_name | string | | |
action_result.data.\*.data.attributes.results.Avira.engine_version | string | | |
action_result.data.\*.data.attributes.results.Avira.engine_update | string | | |
action_result.data.\*.data.attributes.results.Avira.method | string | | |
action_result.data.\*.data.attributes.results.Avira.result | string | | |
action_result.data.\*.data.attributes.results.Avira.vendor | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.category | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.engine_name | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.engine_version | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.engine_update | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.method | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.result | string | | |
action_result.data.\*.data.attributes.results.Antiy_AVL.vendor | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.category | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.method | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.result | string | | |
action_result.data.\*.data.attributes.results.Kingsoft.vendor | string | | |
action_result.data.\*.data.attributes.results.Microsoft.category | string | | |
action_result.data.\*.data.attributes.results.Microsoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Microsoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Microsoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Microsoft.method | string | | |
action_result.data.\*.data.attributes.results.Microsoft.result | string | | |
action_result.data.\*.data.attributes.results.Microsoft.vendor | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.category | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_name | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_version | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.engine_update | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.method | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.result | string | | |
action_result.data.\*.data.attributes.results.Gridinsoft.vendor | string | | |
action_result.data.\*.data.attributes.results.Xcitium.category | string | | |
action_result.data.\*.data.attributes.results.Xcitium.engine_name | string | | |
action_result.data.\*.data.attributes.results.Xcitium.engine_version | string | | |
action_result.data.\*.data.attributes.results.Xcitium.engine_update | string | | |
action_result.data.\*.data.attributes.results.Xcitium.method | string | | |
action_result.data.\*.data.attributes.results.Xcitium.result | string | | |
action_result.data.\*.data.attributes.results.Xcitium.vendor | string | | |
action_result.data.\*.data.attributes.results.Acrabit.category | string | | |
action_result.data.\*.data.attributes.results.Acrabit.engine_name | string | | |
action_result.data.\*.data.attributes.results.Acrabit.engine_version | string | | |
action_result.data.\*.data.attributes.results.Acrabit.engine_update | string | | |
action_result.data.\*.data.attributes.results.Acrabit.method | string | | |
action_result.data.\*.data.attributes.results.Acrabit.result | string | | |
action_result.data.\*.data.attributes.results.Acrabit.vendor | string | | |
action_result.data.\*.data.attributes.results.ViRobot.category | string | | |
action_result.data.\*.data.attributes.results.ViRobot.engine_name | string | | |
action_result.data.\*.data.attributes.results.ViRobot.engine_version | string | | |
action_result.data.\*.data.attributes.results.ViRobot.engine_update | string | | |
action_result.data.\*.data.attributes.results.ViRobot.method | string | | |
action_result.data.\*.data.attributes.results.ViRobot.result | string | | |
action_result.data.\*.data.attributes.results.ViRobot.vendor | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.category | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_name | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_version | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.engine_update | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.method | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.result | string | | |
action_result.data.\*.data.attributes.results.ZoneAlarm.vendor | string | | |
action_result.data.\*.data.attributes.results.GData.category | string | | |
action_result.data.\*.data.attributes.results.GData.engine_name | string | | |
action_result.data.\*.data.attributes.results.GData.engine_version | string | | |
action_result.data.\*.data.attributes.results.GData.engine_update | string | | |
action_result.data.\*.data.attributes.results.GData.method | string | | |
action_result.data.\*.data.attributes.results.GData.result | string | | |
action_result.data.\*.data.attributes.results.GData.vendor | string | | |
action_result.data.\*.data.attributes.results.Varist.category | string | | |
action_result.data.\*.data.attributes.results.Varist.engine_name | string | | |
action_result.data.\*.data.attributes.results.Varist.engine_version | string | | |
action_result.data.\*.data.attributes.results.Varist.engine_update | string | | |
action_result.data.\*.data.attributes.results.Varist.method | string | | |
action_result.data.\*.data.attributes.results.Varist.result | string | | |
action_result.data.\*.data.attributes.results.Varist.vendor | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.category | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.engine_name | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.engine_version | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.engine_update | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.method | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.result | string | | |
action_result.data.\*.data.attributes.results.AhnLab_V3.vendor | string | | |
action_result.data.\*.data.attributes.results.Acronis.category | string | | |
action_result.data.\*.data.attributes.results.Acronis.engine_name | string | | |
action_result.data.\*.data.attributes.results.Acronis.engine_version | string | | |
action_result.data.\*.data.attributes.results.Acronis.engine_update | string | | |
action_result.data.\*.data.attributes.results.Acronis.method | string | | |
action_result.data.\*.data.attributes.results.Acronis.result | string | | |
action_result.data.\*.data.attributes.results.Acronis.vendor | string | | |
action_result.data.\*.data.attributes.results.VBA32.category | string | | |
action_result.data.\*.data.attributes.results.VBA32.engine_name | string | | |
action_result.data.\*.data.attributes.results.VBA32.engine_version | string | | |
action_result.data.\*.data.attributes.results.VBA32.engine_update | string | | |
action_result.data.\*.data.attributes.results.VBA32.method | string | | |
action_result.data.\*.data.attributes.results.VBA32.result | string | | |
action_result.data.\*.data.attributes.results.VBA32.vendor | string | | |
action_result.data.\*.data.attributes.results.TACHYON.category | string | | |
action_result.data.\*.data.attributes.results.TACHYON.engine_name | string | | |
action_result.data.\*.data.attributes.results.TACHYON.engine_version | string | | |
action_result.data.\*.data.attributes.results.TACHYON.engine_update | string | | |
action_result.data.\*.data.attributes.results.TACHYON.method | string | | |
action_result.data.\*.data.attributes.results.TACHYON.result | string | | |
action_result.data.\*.data.attributes.results.TACHYON.vendor | string | | |
action_result.data.\*.data.attributes.results.Zoner.category | string | | |
action_result.data.\*.data.attributes.results.Zoner.engine_name | string | | |
action_result.data.\*.data.attributes.results.Zoner.engine_version | string | | |
action_result.data.\*.data.attributes.results.Zoner.engine_update | string | | |
action_result.data.\*.data.attributes.results.Zoner.method | string | | |
action_result.data.\*.data.attributes.results.Zoner.result | string | | |
action_result.data.\*.data.attributes.results.Zoner.vendor | string | | |
action_result.data.\*.data.attributes.results.Tencent.category | string | | |
action_result.data.\*.data.attributes.results.Tencent.engine_name | string | | |
action_result.data.\*.data.attributes.results.Tencent.engine_version | string | | |
action_result.data.\*.data.attributes.results.Tencent.engine_update | string | | |
action_result.data.\*.data.attributes.results.Tencent.method | string | | |
action_result.data.\*.data.attributes.results.Tencent.result | string | | |
action_result.data.\*.data.attributes.results.Tencent.vendor | string | | |
action_result.data.\*.data.attributes.results.Yandex.category | string | | |
action_result.data.\*.data.attributes.results.Yandex.engine_name | string | | |
action_result.data.\*.data.attributes.results.Yandex.engine_version | string | | |
action_result.data.\*.data.attributes.results.Yandex.engine_update | string | | |
action_result.data.\*.data.attributes.results.Yandex.method | string | | |
action_result.data.\*.data.attributes.results.Yandex.result | string | | |
action_result.data.\*.data.attributes.results.Yandex.vendor | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.category | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.engine_name | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.engine_version | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.engine_update | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.method | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.result | string | | |
action_result.data.\*.data.attributes.results.TrellixENS.vendor | string | | |
action_result.data.\*.data.attributes.results.huorong.category | string | | |
action_result.data.\*.data.attributes.results.huorong.engine_name | string | | |
action_result.data.\*.data.attributes.results.huorong.engine_version | string | | |
action_result.data.\*.data.attributes.results.huorong.engine_update | string | | |
action_result.data.\*.data.attributes.results.huorong.method | string | | |
action_result.data.\*.data.attributes.results.huorong.result | string | | |
action_result.data.\*.data.attributes.results.huorong.vendor | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.category | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.engine_name | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.engine_version | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.engine_update | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.method | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.result | string | | |
action_result.data.\*.data.attributes.results.MaxSecure.vendor | string | | |
action_result.data.\*.data.attributes.results.Fortinet.category | string | | |
action_result.data.\*.data.attributes.results.Fortinet.engine_name | string | | |
action_result.data.\*.data.attributes.results.Fortinet.engine_version | string | | |
action_result.data.\*.data.attributes.results.Fortinet.engine_update | string | | |
action_result.data.\*.data.attributes.results.Fortinet.method | string | | |
action_result.data.\*.data.attributes.results.Fortinet.result | string | | |
action_result.data.\*.data.attributes.results.Fortinet.vendor | string | | |
action_result.data.\*.data.attributes.results.AVG.category | string | | |
action_result.data.\*.data.attributes.results.AVG.engine_name | string | | |
action_result.data.\*.data.attributes.results.AVG.engine_version | string | | |
action_result.data.\*.data.attributes.results.AVG.engine_update | string | | |
action_result.data.\*.data.attributes.results.AVG.method | string | | |
action_result.data.\*.data.attributes.results.AVG.result | string | | |
action_result.data.\*.data.attributes.results.AVG.vendor | string | | |
action_result.data.\*.data.attributes.results.Panda.category | string | | |
action_result.data.\*.data.attributes.results.Panda.engine_name | string | | |
action_result.data.\*.data.attributes.results.Panda.engine_version | string | | |
action_result.data.\*.data.attributes.results.Panda.engine_update | string | | |
action_result.data.\*.data.attributes.results.Panda.method | string | | |
action_result.data.\*.data.attributes.results.Panda.result | string | | |
action_result.data.\*.data.attributes.results.Panda.vendor | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.category | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.engine_name | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.engine_version | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.engine_update | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.method | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.result | string | | |
action_result.data.\*.data.attributes.results.alibabacloud.vendor | string | | |
action_result.data.\*.data.attributes.results.VirIT.category | string | | |
action_result.data.\*.data.attributes.results.VirIT.engine_name | string | | |
action_result.data.\*.data.attributes.results.VirIT.engine_version | string | | |
action_result.data.\*.data.attributes.results.VirIT.engine_update | string | | |
action_result.data.\*.data.attributes.results.VirIT.method | string | | |
action_result.data.\*.data.attributes.results.VirIT.result | string | | |
action_result.data.\*.data.attributes.results.VirIT.vendor | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.category | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.engine_name | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.engine_version | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.engine_update | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.method | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.result | string | | |
action_result.data.\*.data.attributes.results.CAT_QuickHeal.vendor | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.category | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.engine_name | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.engine_version | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.engine_update | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.method | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.result | string | | |
action_result.data.\*.data.attributes.results.Avast_Mobile.vendor | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.category | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_name | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_version | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.engine_update | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.method | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.result | string | | |
action_result.data.\*.data.attributes.results.SymantecMobileInsight.vendor | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.category | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_name | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_version | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.engine_update | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.method | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.result | string | | |
action_result.data.\*.data.attributes.results.BitDefenderFalx.vendor | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.category | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.engine_name | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.engine_version | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.engine_update | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.method | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.result | string | | |
action_result.data.\*.data.attributes.results.DeepInstinct.vendor | string | | |
action_result.data.\*.data.attributes.results.Elastic.category | string | | |
action_result.data.\*.data.attributes.results.Elastic.engine_name | string | | |
action_result.data.\*.data.attributes.results.Elastic.engine_version | string | | |
action_result.data.\*.data.attributes.results.Elastic.engine_update | string | | |
action_result.data.\*.data.attributes.results.Elastic.method | string | | |
action_result.data.\*.data.attributes.results.Elastic.result | string | | |
action_result.data.\*.data.attributes.results.Elastic.vendor | string | | |
action_result.data.\*.data.attributes.results.APEX.category | string | | |
action_result.data.\*.data.attributes.results.APEX.engine_name | string | | |
action_result.data.\*.data.attributes.results.APEX.engine_version | string | | |
action_result.data.\*.data.attributes.results.APEX.engine_update | string | | |
action_result.data.\*.data.attributes.results.APEX.method | string | | |
action_result.data.\*.data.attributes.results.APEX.result | string | | |
action_result.data.\*.data.attributes.results.APEX.vendor | string | | |
action_result.data.\*.data.attributes.results.Paloalto.category | string | | |
action_result.data.\*.data.attributes.results.Paloalto.engine_name | string | | |
action_result.data.\*.data.attributes.results.Paloalto.engine_version | string | | |
action_result.data.\*.data.attributes.results.Paloalto.engine_update | string | | |
action_result.data.\*.data.attributes.results.Paloalto.method | string | | |
action_result.data.\*.data.attributes.results.Paloalto.result | string | | |
action_result.data.\*.data.attributes.results.Paloalto.vendor | string | | |
action_result.data.\*.data.attributes.results.Trapmine.category | string | | |
action_result.data.\*.data.attributes.results.Trapmine.engine_name | string | | |
action_result.data.\*.data.attributes.results.Trapmine.engine_version | string | | |
action_result.data.\*.data.attributes.results.Trapmine.engine_update | string | | |
action_result.data.\*.data.attributes.results.Trapmine.method | string | | |
action_result.data.\*.data.attributes.results.Trapmine.result | string | | |
action_result.data.\*.data.attributes.results.Trapmine.vendor | string | | |
action_result.data.\*.data.attributes.results.Alibaba.category | string | | |
action_result.data.\*.data.attributes.results.Alibaba.engine_name | string | | |
action_result.data.\*.data.attributes.results.Alibaba.engine_version | string | | |
action_result.data.\*.data.attributes.results.Alibaba.engine_update | string | | |
action_result.data.\*.data.attributes.results.Alibaba.method | string | | |
action_result.data.\*.data.attributes.results.Alibaba.result | string | | |
action_result.data.\*.data.attributes.results.Alibaba.vendor | string | | |
action_result.data.\*.data.attributes.results.Webroot.category | string | | |
action_result.data.\*.data.attributes.results.Webroot.engine_name | string | | |
action_result.data.\*.data.attributes.results.Webroot.engine_version | string | | |
action_result.data.\*.data.attributes.results.Webroot.engine_update | string | | |
action_result.data.\*.data.attributes.results.Webroot.method | string | | |
action_result.data.\*.data.attributes.results.Webroot.result | string | | |
action_result.data.\*.data.attributes.results.Webroot.vendor | string | | |
action_result.data.\*.data.attributes.results.Cylance.category | string | | |
action_result.data.\*.data.attributes.results.Cylance.engine_name | string | | |
action_result.data.\*.data.attributes.results.Cylance.engine_version | string | | |
action_result.data.\*.data.attributes.results.Cylance.engine_update | string | | |
action_result.data.\*.data.attributes.results.Cylance.method | string | | |
action_result.data.\*.data.attributes.results.Cylance.result | string | | |
action_result.data.\*.data.attributes.results.Cylance.vendor | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.category | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.engine_name | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.engine_version | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.engine_update | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.method | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.result | string | | |
action_result.data.\*.data.attributes.results.SentinelOne.vendor | string | | |
action_result.data.\*.data.attributes.results.tehtris.category | string | | |
action_result.data.\*.data.attributes.results.tehtris.engine_name | string | | |
action_result.data.\*.data.attributes.results.tehtris.engine_version | string | | |
action_result.data.\*.data.attributes.results.tehtris.engine_update | string | | |
action_result.data.\*.data.attributes.results.tehtris.method | string | | |
action_result.data.\*.data.attributes.results.tehtris.result | string | | |
action_result.data.\*.data.attributes.results.tehtris.vendor | string | | |
action_result.data.\*.data.attributes.results.Trustlook.category | string | | |
action_result.data.\*.data.attributes.results.Trustlook.engine_name | string | | |
action_result.data.\*.data.attributes.results.Trustlook.engine_version | string | | |
action_result.data.\*.data.attributes.results.Trustlook.engine_update | string | | |
action_result.data.\*.data.attributes.results.Trustlook.method | string | | |
action_result.data.\*.data.attributes.results.Trustlook.result | string | | |
action_result.data.\*.data.attributes.results.Trustlook.vendor | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.category | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.engine_name | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.engine_version | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.engine_update | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.method | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.result | string | | |
action_result.data.\*.data.attributes.results.OpenPhish.vendor | string | | |
action_result.data.\*.data.attributes.results.Nucleon.category | string | | |
action_result.data.\*.data.attributes.results.Nucleon.engine_name | string | | |
action_result.data.\*.data.attributes.results.Nucleon.engine_version | string | | |
action_result.data.\*.data.attributes.results.Nucleon.engine_update | string | | |
action_result.data.\*.data.attributes.results.Nucleon.method | string | | |
action_result.data.\*.data.attributes.results.Nucleon.result | string | | |
action_result.data.\*.data.attributes.results.Nucleon.vendor | string | | |
action_result.data.\*.data.attributes.stats.malicious | numeric | | |
action_result.data.\*.data.attributes.stats.suspicious | numeric | | |
action_result.data.\*.data.attributes.stats.undetected | numeric | | |
action_result.data.\*.data.attributes.stats.harmless | numeric | | |
action_result.data.\*.data.attributes.stats.timeout | numeric | | |
action_result.data.\*.data.attributes.stats.confirmed_timeout | numeric | | |
action_result.data.\*.data.attributes.stats.failure | numeric | | |
action_result.data.\*.data.attributes.stats.type_unsupported | numeric | | |
action_result.data.\*.data.attributes.status | string | | completed |
action_result.data.\*.data.id | string | `virustotal scan id` | MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw== |
action_result.data.\*.data.links.item | string | | https://www.virustotal.com/api/v3/files/917c72a2684d1573ea363b2f91e3aedcef1996fc34668ba9d369ad9123d1380f |
action_result.data.\*.data.links.self | string | | https://www.virustotal.com/api/v3/analyses/ZDhhNjY5NmU2NDJlYzUyMDUwMmEwNWE0YWRkOGMxNzk6MTY3ODY4OTQ5Mg== |
action_result.data.\*.data.type | string | | |
action_result.data.\*.data.meta.file_info.md5 | string | `md5` | 299999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.data.meta.file_info.name | string | | update_cr.py |
action_result.data.\*.data.meta.file_info.sha1 | string | `sha1` | 9999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.data.meta.file_info.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.data.meta.file_info.size | numeric | | 6285 |
action_result.data.\*.data.meta.url_info.id | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.data.meta.url_info.url | string | | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.id | string | `sha256` | 9999999999e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.links.self | string | `url` | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.meta.file_info.md5 | string | `md5` | 299999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.meta.file_info.name | string | | update_cr.py |
action_result.data.\*.meta.file_info.sha1 | string | `sha1` | 9999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.meta.file_info.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.file_info.size | numeric | | 6285 |
action_result.data.\*.meta.url_info.id | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.url_info.url | string | | https://www.virustotal.com/api/v3/domains/test.com |
action_result.data.\*.type | string | | file |
action_result.data.\*.scan_id | string | | |
action_result.summary.scan_id | string | | |
action_result.summary.harmless | numeric | | |
action_result.summary.malicious | numeric | | |
action_result.summary.suspicious | numeric | | |
action_result.summary.timeout | numeric | | |
action_result.summary.undetected | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Get the results using the scan id from a detonate file or detonate url action

Type: **investigate** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.scan_id | string | `virustotal scan id` | |
action_result.parameter.wait_time | numeric | | |
action_result.data.\*.attributes.date | numeric | `timestamp` | 1613651763 |
action_result.data.\*.attributes.results.Bkav.category | string | | |
action_result.data.\*.attributes.results.Bkav.engine_name | string | | |
action_result.data.\*.attributes.results.Bkav.engine_version | string | | |
action_result.data.\*.attributes.results.Bkav.engine_update | string | | |
action_result.data.\*.attributes.results.Bkav.method | string | | |
action_result.data.\*.attributes.results.Bkav.result | string | | |
action_result.data.\*.attributes.results.Bkav.vendor | string | | |
action_result.data.\*.attributes.results.Lionic.category | string | | |
action_result.data.\*.attributes.results.Lionic.engine_name | string | | |
action_result.data.\*.attributes.results.Lionic.engine_version | string | | |
action_result.data.\*.attributes.results.Lionic.engine_update | string | | |
action_result.data.\*.attributes.results.Lionic.method | string | | |
action_result.data.\*.attributes.results.Lionic.result | string | | |
action_result.data.\*.attributes.results.Lionic.vendor | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.category | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.engine_name | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.engine_version | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.engine_update | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.method | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.result | string | | |
action_result.data.\*.attributes.results.MicroWorld_eScan.vendor | string | | |
action_result.data.\*.attributes.results.ClamAV.category | string | | |
action_result.data.\*.attributes.results.ClamAV.engine_name | string | | |
action_result.data.\*.attributes.results.ClamAV.engine_version | string | | |
action_result.data.\*.attributes.results.ClamAV.engine_update | string | | |
action_result.data.\*.attributes.results.ClamAV.method | string | | |
action_result.data.\*.attributes.results.ClamAV.result | string | | |
action_result.data.\*.attributes.results.ClamAV.vendor | string | | |
action_result.data.\*.attributes.results.CTX.category | string | | |
action_result.data.\*.attributes.results.CTX.engine_name | string | | |
action_result.data.\*.attributes.results.CTX.engine_version | string | | |
action_result.data.\*.attributes.results.CTX.engine_update | string | | |
action_result.data.\*.attributes.results.CTX.method | string | | |
action_result.data.\*.attributes.results.CTX.result | string | | |
action_result.data.\*.attributes.results.CTX.vendor | string | | |
action_result.data.\*.attributes.results.Skyhigh.category | string | | |
action_result.data.\*.attributes.results.Skyhigh.engine_name | string | | |
action_result.data.\*.attributes.results.Skyhigh.engine_version | string | | |
action_result.data.\*.attributes.results.Skyhigh.engine_update | string | | |
action_result.data.\*.attributes.results.Skyhigh.method | string | | |
action_result.data.\*.attributes.results.Skyhigh.result | string | | |
action_result.data.\*.attributes.results.Skyhigh.vendor | string | | |
action_result.data.\*.attributes.results.ALYac.category | string | | |
action_result.data.\*.attributes.results.ALYac.engine_name | string | | |
action_result.data.\*.attributes.results.ALYac.engine_version | string | | |
action_result.data.\*.attributes.results.ALYac.engine_update | string | | |
action_result.data.\*.attributes.results.ALYac.method | string | | |
action_result.data.\*.attributes.results.ALYac.result | string | | |
action_result.data.\*.attributes.results.ALYac.vendor | string | | |
action_result.data.\*.attributes.results.Malwarebytes.category | string | | |
action_result.data.\*.attributes.results.Malwarebytes.engine_name | string | | |
action_result.data.\*.attributes.results.Malwarebytes.engine_version | string | | |
action_result.data.\*.attributes.results.Malwarebytes.engine_update | string | | |
action_result.data.\*.attributes.results.Malwarebytes.method | string | | |
action_result.data.\*.attributes.results.Malwarebytes.result | string | | |
action_result.data.\*.attributes.results.Malwarebytes.vendor | string | | |
action_result.data.\*.attributes.results.Zillya.category | string | | |
action_result.data.\*.attributes.results.Zillya.engine_name | string | | |
action_result.data.\*.attributes.results.Zillya.engine_version | string | | |
action_result.data.\*.attributes.results.Zillya.engine_update | string | | |
action_result.data.\*.attributes.results.Zillya.method | string | | |
action_result.data.\*.attributes.results.Zillya.result | string | | |
action_result.data.\*.attributes.results.Zillya.vendor | string | | |
action_result.data.\*.attributes.results.Sangfor.category | string | | |
action_result.data.\*.attributes.results.Sangfor.engine_name | string | | |
action_result.data.\*.attributes.results.Sangfor.engine_version | string | | |
action_result.data.\*.attributes.results.Sangfor.engine_update | string | | |
action_result.data.\*.attributes.results.Sangfor.method | string | | |
action_result.data.\*.attributes.results.Sangfor.result | string | | |
action_result.data.\*.attributes.results.Sangfor.vendor | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.category | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.engine_name | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.engine_version | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.engine_update | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.method | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.result | string | | |
action_result.data.\*.attributes.results.K7AntiVirus.vendor | string | | |
action_result.data.\*.attributes.results.K7GW.category | string | | |
action_result.data.\*.attributes.results.K7GW.engine_name | string | | |
action_result.data.\*.attributes.results.K7GW.engine_version | string | | |
action_result.data.\*.attributes.results.K7GW.engine_update | string | | |
action_result.data.\*.attributes.results.K7GW.method | string | | |
action_result.data.\*.attributes.results.K7GW.result | string | | |
action_result.data.\*.attributes.results.K7GW.vendor | string | | |
action_result.data.\*.attributes.results.CrowdStrike.category | string | | |
action_result.data.\*.attributes.results.CrowdStrike.engine_name | string | | |
action_result.data.\*.attributes.results.CrowdStrike.engine_version | string | | |
action_result.data.\*.attributes.results.CrowdStrike.engine_update | string | | |
action_result.data.\*.attributes.results.CrowdStrike.method | string | | |
action_result.data.\*.attributes.results.CrowdStrike.result | string | | |
action_result.data.\*.attributes.results.CrowdStrike.vendor | string | | |
action_result.data.\*.attributes.results.Baidu.category | string | | |
action_result.data.\*.attributes.results.Baidu.engine_name | string | | |
action_result.data.\*.attributes.results.Baidu.engine_version | string | | |
action_result.data.\*.attributes.results.Baidu.engine_update | string | | |
action_result.data.\*.attributes.results.Baidu.method | string | | |
action_result.data.\*.attributes.results.Baidu.result | string | | |
action_result.data.\*.attributes.results.Baidu.vendor | string | | |
action_result.data.\*.attributes.results.Symantec.category | string | | |
action_result.data.\*.attributes.results.Symantec.engine_name | string | | |
action_result.data.\*.attributes.results.Symantec.engine_version | string | | |
action_result.data.\*.attributes.results.Symantec.engine_update | string | | |
action_result.data.\*.attributes.results.Symantec.method | string | | |
action_result.data.\*.attributes.results.Symantec.result | string | | |
action_result.data.\*.attributes.results.Symantec.vendor | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.category | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.engine_name | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.engine_version | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.engine_update | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.method | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.result | string | | |
action_result.data.\*.attributes.results.ESET_NOD32.vendor | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.category | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.engine_name | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.engine_version | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.engine_update | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.method | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.result | string | | |
action_result.data.\*.attributes.results.TrendMicro_HouseCall.vendor | string | | |
action_result.data.\*.attributes.results.Avast.category | string | | |
action_result.data.\*.attributes.results.Avast.engine_name | string | | |
action_result.data.\*.attributes.results.Avast.engine_version | string | | |
action_result.data.\*.attributes.results.Avast.engine_update | string | | |
action_result.data.\*.attributes.results.Avast.method | string | | |
action_result.data.\*.attributes.results.Avast.result | string | | |
action_result.data.\*.attributes.results.Avast.vendor | string | | |
action_result.data.\*.attributes.results.Cynet.category | string | | |
action_result.data.\*.attributes.results.Cynet.engine_name | string | | |
action_result.data.\*.attributes.results.Cynet.engine_version | string | | |
action_result.data.\*.attributes.results.Cynet.engine_update | string | | |
action_result.data.\*.attributes.results.Cynet.method | string | | |
action_result.data.\*.attributes.results.Cynet.result | string | | |
action_result.data.\*.attributes.results.Cynet.vendor | string | | |
action_result.data.\*.attributes.results.Kaspersky.category | string | | |
action_result.data.\*.attributes.results.Kaspersky.engine_name | string | | |
action_result.data.\*.attributes.results.Kaspersky.engine_version | string | | |
action_result.data.\*.attributes.results.Kaspersky.engine_update | string | | |
action_result.data.\*.attributes.results.Kaspersky.method | string | | |
action_result.data.\*.attributes.results.Kaspersky.result | string | | |
action_result.data.\*.attributes.results.Kaspersky.vendor | string | | |
action_result.data.\*.attributes.results.BitDefender.category | string | | |
action_result.data.\*.attributes.results.BitDefender.engine_name | string | | |
action_result.data.\*.attributes.results.BitDefender.engine_version | string | | |
action_result.data.\*.attributes.results.BitDefender.engine_update | string | | |
action_result.data.\*.attributes.results.BitDefender.method | string | | |
action_result.data.\*.attributes.results.BitDefender.result | string | | |
action_result.data.\*.attributes.results.BitDefender.vendor | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.category | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.engine_name | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.engine_version | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.engine_update | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.method | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.result | string | | |
action_result.data.\*.attributes.results.NANO_Antivirus.vendor | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.category | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.engine_name | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.engine_version | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.engine_update | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.method | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.result | string | | |
action_result.data.\*.attributes.results.SUPERAntiSpyware.vendor | string | | |
action_result.data.\*.attributes.results.Rising.category | string | | |
action_result.data.\*.attributes.results.Rising.engine_name | string | | |
action_result.data.\*.attributes.results.Rising.engine_version | string | | |
action_result.data.\*.attributes.results.Rising.engine_update | string | | |
action_result.data.\*.attributes.results.Rising.method | string | | |
action_result.data.\*.attributes.results.Rising.result | string | | |
action_result.data.\*.attributes.results.Rising.vendor | string | | |
action_result.data.\*.attributes.results.Emsisoft.category | string | | |
action_result.data.\*.attributes.results.Emsisoft.engine_name | string | | |
action_result.data.\*.attributes.results.Emsisoft.engine_version | string | | |
action_result.data.\*.attributes.results.Emsisoft.engine_update | string | | |
action_result.data.\*.attributes.results.Emsisoft.method | string | | |
action_result.data.\*.attributes.results.Emsisoft.result | string | | |
action_result.data.\*.attributes.results.Emsisoft.vendor | string | | |
action_result.data.\*.attributes.results.F_Secure.category | string | | |
action_result.data.\*.attributes.results.F_Secure.engine_name | string | | |
action_result.data.\*.attributes.results.F_Secure.engine_version | string | | |
action_result.data.\*.attributes.results.F_Secure.engine_update | string | | |
action_result.data.\*.attributes.results.F_Secure.method | string | | |
action_result.data.\*.attributes.results.F_Secure.result | string | | |
action_result.data.\*.attributes.results.F_Secure.vendor | string | | |
action_result.data.\*.attributes.results.DrWeb.category | string | | |
action_result.data.\*.attributes.results.DrWeb.engine_name | string | | |
action_result.data.\*.attributes.results.DrWeb.engine_version | string | | |
action_result.data.\*.attributes.results.DrWeb.engine_update | string | | |
action_result.data.\*.attributes.results.DrWeb.method | string | | |
action_result.data.\*.attributes.results.DrWeb.result | string | | |
action_result.data.\*.attributes.results.DrWeb.vendor | string | | |
action_result.data.\*.attributes.results.VIPRE.category | string | | |
action_result.data.\*.attributes.results.VIPRE.engine_name | string | | |
action_result.data.\*.attributes.results.VIPRE.engine_version | string | | |
action_result.data.\*.attributes.results.VIPRE.engine_update | string | | |
action_result.data.\*.attributes.results.VIPRE.method | string | | |
action_result.data.\*.attributes.results.VIPRE.result | string | | |
action_result.data.\*.attributes.results.VIPRE.vendor | string | | |
action_result.data.\*.attributes.results.TrendMicro.category | string | | |
action_result.data.\*.attributes.results.TrendMicro.engine_name | string | | |
action_result.data.\*.attributes.results.TrendMicro.engine_version | string | | |
action_result.data.\*.attributes.results.TrendMicro.engine_update | string | | |
action_result.data.\*.attributes.results.TrendMicro.method | string | | |
action_result.data.\*.attributes.results.TrendMicro.result | string | | |
action_result.data.\*.attributes.results.TrendMicro.vendor | string | | |
action_result.data.\*.attributes.results.McAfeeD.category | string | | |
action_result.data.\*.attributes.results.McAfeeD.engine_name | string | | |
action_result.data.\*.attributes.results.McAfeeD.engine_version | string | | |
action_result.data.\*.attributes.results.McAfeeD.engine_update | string | | |
action_result.data.\*.attributes.results.McAfeeD.method | string | | |
action_result.data.\*.attributes.results.McAfeeD.result | string | | |
action_result.data.\*.attributes.results.McAfeeD.vendor | string | | |
action_result.data.\*.attributes.results.CMC.category | string | | |
action_result.data.\*.attributes.results.CMC.engine_name | string | | |
action_result.data.\*.attributes.results.CMC.engine_version | string | | |
action_result.data.\*.attributes.results.CMC.engine_update | string | | |
action_result.data.\*.attributes.results.CMC.method | string | | |
action_result.data.\*.attributes.results.CMC.result | string | | |
action_result.data.\*.attributes.results.CMC.vendor | string | | |
action_result.data.\*.attributes.results.Sophos.category | string | | |
action_result.data.\*.attributes.results.Sophos.engine_name | string | | |
action_result.data.\*.attributes.results.Sophos.engine_version | string | | |
action_result.data.\*.attributes.results.Sophos.engine_update | string | | |
action_result.data.\*.attributes.results.Sophos.method | string | | |
action_result.data.\*.attributes.results.Sophos.result | string | | |
action_result.data.\*.attributes.results.Sophos.vendor | string | | |
action_result.data.\*.attributes.results.Ikarus.category | string | | |
action_result.data.\*.attributes.results.Ikarus.engine_name | string | | |
action_result.data.\*.attributes.results.Ikarus.engine_version | string | | |
action_result.data.\*.attributes.results.Ikarus.engine_update | string | | |
action_result.data.\*.attributes.results.Ikarus.method | string | | |
action_result.data.\*.attributes.results.Ikarus.result | string | | |
action_result.data.\*.attributes.results.Ikarus.vendor | string | | |
action_result.data.\*.attributes.results.Jiangmin.category | string | | |
action_result.data.\*.attributes.results.Jiangmin.engine_name | string | | |
action_result.data.\*.attributes.results.Jiangmin.engine_version | string | | |
action_result.data.\*.attributes.results.Jiangmin.engine_update | string | | |
action_result.data.\*.attributes.results.Jiangmin.method | string | | |
action_result.data.\*.attributes.results.Jiangmin.result | string | | |
action_result.data.\*.attributes.results.Jiangmin.vendor | string | | |
action_result.data.\*.attributes.results.Google.category | string | | |
action_result.data.\*.attributes.results.Google.engine_name | string | | |
action_result.data.\*.attributes.results.Google.engine_version | string | | |
action_result.data.\*.attributes.results.Google.engine_update | string | | |
action_result.data.\*.attributes.results.Google.method | string | | |
action_result.data.\*.attributes.results.Google.result | string | | |
action_result.data.\*.attributes.results.Google.vendor | string | | |
action_result.data.\*.attributes.results.Avira.category | string | | |
action_result.data.\*.attributes.results.Avira.engine_name | string | | |
action_result.data.\*.attributes.results.Avira.engine_version | string | | |
action_result.data.\*.attributes.results.Avira.engine_update | string | | |
action_result.data.\*.attributes.results.Avira.method | string | | |
action_result.data.\*.attributes.results.Avira.result | string | | |
action_result.data.\*.attributes.results.Avira.vendor | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.category | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.engine_name | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.engine_version | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.engine_update | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.method | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.result | string | | |
action_result.data.\*.attributes.results.Antiy_AVL.vendor | string | | |
action_result.data.\*.attributes.results.Kingsoft.category | string | | |
action_result.data.\*.attributes.results.Kingsoft.engine_name | string | | |
action_result.data.\*.attributes.results.Kingsoft.engine_version | string | | |
action_result.data.\*.attributes.results.Kingsoft.engine_update | string | | |
action_result.data.\*.attributes.results.Kingsoft.method | string | | |
action_result.data.\*.attributes.results.Kingsoft.result | string | | |
action_result.data.\*.attributes.results.Kingsoft.vendor | string | | |
action_result.data.\*.attributes.results.Microsoft.category | string | | |
action_result.data.\*.attributes.results.Microsoft.engine_name | string | | |
action_result.data.\*.attributes.results.Microsoft.engine_version | string | | |
action_result.data.\*.attributes.results.Microsoft.engine_update | string | | |
action_result.data.\*.attributes.results.Microsoft.method | string | | |
action_result.data.\*.attributes.results.Microsoft.result | string | | |
action_result.data.\*.attributes.results.Microsoft.vendor | string | | |
action_result.data.\*.attributes.results.Gridinsoft.category | string | | |
action_result.data.\*.attributes.results.Gridinsoft.engine_name | string | | |
action_result.data.\*.attributes.results.Gridinsoft.engine_version | string | | |
action_result.data.\*.attributes.results.Gridinsoft.engine_update | string | | |
action_result.data.\*.attributes.results.Gridinsoft.method | string | | |
action_result.data.\*.attributes.results.Gridinsoft.result | string | | |
action_result.data.\*.attributes.results.Gridinsoft.vendor | string | | |
action_result.data.\*.attributes.results.Xcitium.category | string | | |
action_result.data.\*.attributes.results.Xcitium.engine_name | string | | |
action_result.data.\*.attributes.results.Xcitium.engine_version | string | | |
action_result.data.\*.attributes.results.Xcitium.engine_update | string | | |
action_result.data.\*.attributes.results.Xcitium.method | string | | |
action_result.data.\*.attributes.results.Xcitium.result | string | | |
action_result.data.\*.attributes.results.Xcitium.vendor | string | | |
action_result.data.\*.attributes.results.Acrabit.category | string | | |
action_result.data.\*.attributes.results.Acrabit.engine_name | string | | |
action_result.data.\*.attributes.results.Acrabit.engine_version | string | | |
action_result.data.\*.attributes.results.Acrabit.engine_update | string | | |
action_result.data.\*.attributes.results.Acrabit.method | string | | |
action_result.data.\*.attributes.results.Acrabit.result | string | | |
action_result.data.\*.attributes.results.Acrabit.vendor | string | | |
action_result.data.\*.attributes.results.ViRobot.category | string | | |
action_result.data.\*.attributes.results.ViRobot.engine_name | string | | |
action_result.data.\*.attributes.results.ViRobot.engine_version | string | | |
action_result.data.\*.attributes.results.ViRobot.engine_update | string | | |
action_result.data.\*.attributes.results.ViRobot.method | string | | |
action_result.data.\*.attributes.results.ViRobot.result | string | | |
action_result.data.\*.attributes.results.ViRobot.vendor | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.category | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.engine_name | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.engine_version | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.engine_update | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.method | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.result | string | | |
action_result.data.\*.attributes.results.ZoneAlarm.vendor | string | | |
action_result.data.\*.attributes.results.GData.category | string | | |
action_result.data.\*.attributes.results.GData.engine_name | string | | |
action_result.data.\*.attributes.results.GData.engine_version | string | | |
action_result.data.\*.attributes.results.GData.engine_update | string | | |
action_result.data.\*.attributes.results.GData.method | string | | |
action_result.data.\*.attributes.results.GData.result | string | | |
action_result.data.\*.attributes.results.GData.vendor | string | | |
action_result.data.\*.attributes.results.Varist.category | string | | |
action_result.data.\*.attributes.results.Varist.engine_name | string | | |
action_result.data.\*.attributes.results.Varist.engine_version | string | | |
action_result.data.\*.attributes.results.Varist.engine_update | string | | |
action_result.data.\*.attributes.results.Varist.method | string | | |
action_result.data.\*.attributes.results.Varist.result | string | | |
action_result.data.\*.attributes.results.Varist.vendor | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.category | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.engine_name | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.engine_version | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.engine_update | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.method | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.result | string | | |
action_result.data.\*.attributes.results.AhnLab_V3.vendor | string | | |
action_result.data.\*.attributes.results.Acronis.category | string | | |
action_result.data.\*.attributes.results.Acronis.engine_name | string | | |
action_result.data.\*.attributes.results.Acronis.engine_version | string | | |
action_result.data.\*.attributes.results.Acronis.engine_update | string | | |
action_result.data.\*.attributes.results.Acronis.method | string | | |
action_result.data.\*.attributes.results.Acronis.result | string | | |
action_result.data.\*.attributes.results.Acronis.vendor | string | | |
action_result.data.\*.attributes.results.VBA32.category | string | | |
action_result.data.\*.attributes.results.VBA32.engine_name | string | | |
action_result.data.\*.attributes.results.VBA32.engine_version | string | | |
action_result.data.\*.attributes.results.VBA32.engine_update | string | | |
action_result.data.\*.attributes.results.VBA32.method | string | | |
action_result.data.\*.attributes.results.VBA32.result | string | | |
action_result.data.\*.attributes.results.VBA32.vendor | string | | |
action_result.data.\*.attributes.results.TACHYON.category | string | | |
action_result.data.\*.attributes.results.TACHYON.engine_name | string | | |
action_result.data.\*.attributes.results.TACHYON.engine_version | string | | |
action_result.data.\*.attributes.results.TACHYON.engine_update | string | | |
action_result.data.\*.attributes.results.TACHYON.method | string | | |
action_result.data.\*.attributes.results.TACHYON.result | string | | |
action_result.data.\*.attributes.results.TACHYON.vendor | string | | |
action_result.data.\*.attributes.results.Zoner.category | string | | |
action_result.data.\*.attributes.results.Zoner.engine_name | string | | |
action_result.data.\*.attributes.results.Zoner.engine_version | string | | |
action_result.data.\*.attributes.results.Zoner.engine_update | string | | |
action_result.data.\*.attributes.results.Zoner.method | string | | |
action_result.data.\*.attributes.results.Zoner.result | string | | |
action_result.data.\*.attributes.results.Zoner.vendor | string | | |
action_result.data.\*.attributes.results.Tencent.category | string | | |
action_result.data.\*.attributes.results.Tencent.engine_name | string | | |
action_result.data.\*.attributes.results.Tencent.engine_version | string | | |
action_result.data.\*.attributes.results.Tencent.engine_update | string | | |
action_result.data.\*.attributes.results.Tencent.method | string | | |
action_result.data.\*.attributes.results.Tencent.result | string | | |
action_result.data.\*.attributes.results.Tencent.vendor | string | | |
action_result.data.\*.attributes.results.Yandex.category | string | | |
action_result.data.\*.attributes.results.Yandex.engine_name | string | | |
action_result.data.\*.attributes.results.Yandex.engine_version | string | | |
action_result.data.\*.attributes.results.Yandex.engine_update | string | | |
action_result.data.\*.attributes.results.Yandex.method | string | | |
action_result.data.\*.attributes.results.Yandex.result | string | | |
action_result.data.\*.attributes.results.Yandex.vendor | string | | |
action_result.data.\*.attributes.results.TrellixENS.category | string | | |
action_result.data.\*.attributes.results.TrellixENS.engine_name | string | | |
action_result.data.\*.attributes.results.TrellixENS.engine_version | string | | |
action_result.data.\*.attributes.results.TrellixENS.engine_update | string | | |
action_result.data.\*.attributes.results.TrellixENS.method | string | | |
action_result.data.\*.attributes.results.TrellixENS.result | string | | |
action_result.data.\*.attributes.results.TrellixENS.vendor | string | | |
action_result.data.\*.attributes.results.huorong.category | string | | |
action_result.data.\*.attributes.results.huorong.engine_name | string | | |
action_result.data.\*.attributes.results.huorong.engine_version | string | | |
action_result.data.\*.attributes.results.huorong.engine_update | string | | |
action_result.data.\*.attributes.results.huorong.method | string | | |
action_result.data.\*.attributes.results.huorong.result | string | | |
action_result.data.\*.attributes.results.huorong.vendor | string | | |
action_result.data.\*.attributes.results.MaxSecure.category | string | | |
action_result.data.\*.attributes.results.MaxSecure.engine_name | string | | |
action_result.data.\*.attributes.results.MaxSecure.engine_version | string | | |
action_result.data.\*.attributes.results.MaxSecure.engine_update | string | | |
action_result.data.\*.attributes.results.MaxSecure.method | string | | |
action_result.data.\*.attributes.results.MaxSecure.result | string | | |
action_result.data.\*.attributes.results.MaxSecure.vendor | string | | |
action_result.data.\*.attributes.results.Fortinet.category | string | | |
action_result.data.\*.attributes.results.Fortinet.engine_name | string | | |
action_result.data.\*.attributes.results.Fortinet.engine_version | string | | |
action_result.data.\*.attributes.results.Fortinet.engine_update | string | | |
action_result.data.\*.attributes.results.Fortinet.method | string | | |
action_result.data.\*.attributes.results.Fortinet.result | string | | |
action_result.data.\*.attributes.results.Fortinet.vendor | string | | |
action_result.data.\*.attributes.results.AVG.category | string | | |
action_result.data.\*.attributes.results.AVG.engine_name | string | | |
action_result.data.\*.attributes.results.AVG.engine_version | string | | |
action_result.data.\*.attributes.results.AVG.engine_update | string | | |
action_result.data.\*.attributes.results.AVG.method | string | | |
action_result.data.\*.attributes.results.AVG.result | string | | |
action_result.data.\*.attributes.results.AVG.vendor | string | | |
action_result.data.\*.attributes.results.Panda.category | string | | |
action_result.data.\*.attributes.results.Panda.engine_name | string | | |
action_result.data.\*.attributes.results.Panda.engine_version | string | | |
action_result.data.\*.attributes.results.Panda.engine_update | string | | |
action_result.data.\*.attributes.results.Panda.method | string | | |
action_result.data.\*.attributes.results.Panda.result | string | | |
action_result.data.\*.attributes.results.Panda.vendor | string | | |
action_result.data.\*.attributes.results.alibabacloud.category | string | | |
action_result.data.\*.attributes.results.alibabacloud.engine_name | string | | |
action_result.data.\*.attributes.results.alibabacloud.engine_version | string | | |
action_result.data.\*.attributes.results.alibabacloud.engine_update | string | | |
action_result.data.\*.attributes.results.alibabacloud.method | string | | |
action_result.data.\*.attributes.results.alibabacloud.result | string | | |
action_result.data.\*.attributes.results.alibabacloud.vendor | string | | |
action_result.data.\*.attributes.results.VirIT.category | string | | |
action_result.data.\*.attributes.results.VirIT.engine_name | string | | |
action_result.data.\*.attributes.results.VirIT.engine_version | string | | |
action_result.data.\*.attributes.results.VirIT.engine_update | string | | |
action_result.data.\*.attributes.results.VirIT.method | string | | |
action_result.data.\*.attributes.results.VirIT.result | string | | |
action_result.data.\*.attributes.results.VirIT.vendor | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.category | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.engine_name | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.engine_version | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.engine_update | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.method | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.result | string | | |
action_result.data.\*.attributes.results.CAT_QuickHeal.vendor | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.category | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.engine_name | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.engine_version | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.engine_update | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.method | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.result | string | | |
action_result.data.\*.attributes.results.Avast_Mobile.vendor | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.category | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.engine_name | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.engine_version | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.engine_update | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.method | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.result | string | | |
action_result.data.\*.attributes.results.SymantecMobileInsight.vendor | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.category | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.engine_name | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.engine_version | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.engine_update | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.method | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.result | string | | |
action_result.data.\*.attributes.results.BitDefenderFalx.vendor | string | | |
action_result.data.\*.attributes.results.DeepInstinct.category | string | | |
action_result.data.\*.attributes.results.DeepInstinct.engine_name | string | | |
action_result.data.\*.attributes.results.DeepInstinct.engine_version | string | | |
action_result.data.\*.attributes.results.DeepInstinct.engine_update | string | | |
action_result.data.\*.attributes.results.DeepInstinct.method | string | | |
action_result.data.\*.attributes.results.DeepInstinct.result | string | | |
action_result.data.\*.attributes.results.DeepInstinct.vendor | string | | |
action_result.data.\*.attributes.results.Elastic.category | string | | |
action_result.data.\*.attributes.results.Elastic.engine_name | string | | |
action_result.data.\*.attributes.results.Elastic.engine_version | string | | |
action_result.data.\*.attributes.results.Elastic.engine_update | string | | |
action_result.data.\*.attributes.results.Elastic.method | string | | |
action_result.data.\*.attributes.results.Elastic.result | string | | |
action_result.data.\*.attributes.results.Elastic.vendor | string | | |
action_result.data.\*.attributes.results.APEX.category | string | | |
action_result.data.\*.attributes.results.APEX.engine_name | string | | |
action_result.data.\*.attributes.results.APEX.engine_version | string | | |
action_result.data.\*.attributes.results.APEX.engine_update | string | | |
action_result.data.\*.attributes.results.APEX.method | string | | |
action_result.data.\*.attributes.results.APEX.result | string | | |
action_result.data.\*.attributes.results.APEX.vendor | string | | |
action_result.data.\*.attributes.results.Paloalto.category | string | | |
action_result.data.\*.attributes.results.Paloalto.engine_name | string | | |
action_result.data.\*.attributes.results.Paloalto.engine_version | string | | |
action_result.data.\*.attributes.results.Paloalto.engine_update | string | | |
action_result.data.\*.attributes.results.Paloalto.method | string | | |
action_result.data.\*.attributes.results.Paloalto.result | string | | |
action_result.data.\*.attributes.results.Paloalto.vendor | string | | |
action_result.data.\*.attributes.results.Trapmine.category | string | | |
action_result.data.\*.attributes.results.Trapmine.engine_name | string | | |
action_result.data.\*.attributes.results.Trapmine.engine_version | string | | |
action_result.data.\*.attributes.results.Trapmine.engine_update | string | | |
action_result.data.\*.attributes.results.Trapmine.method | string | | |
action_result.data.\*.attributes.results.Trapmine.result | string | | |
action_result.data.\*.attributes.results.Trapmine.vendor | string | | |
action_result.data.\*.attributes.results.Alibaba.category | string | | |
action_result.data.\*.attributes.results.Alibaba.engine_name | string | | |
action_result.data.\*.attributes.results.Alibaba.engine_version | string | | |
action_result.data.\*.attributes.results.Alibaba.engine_update | string | | |
action_result.data.\*.attributes.results.Alibaba.method | string | | |
action_result.data.\*.attributes.results.Alibaba.result | string | | |
action_result.data.\*.attributes.results.Alibaba.vendor | string | | |
action_result.data.\*.attributes.results.Webroot.category | string | | |
action_result.data.\*.attributes.results.Webroot.engine_name | string | | |
action_result.data.\*.attributes.results.Webroot.engine_version | string | | |
action_result.data.\*.attributes.results.Webroot.engine_update | string | | |
action_result.data.\*.attributes.results.Webroot.method | string | | |
action_result.data.\*.attributes.results.Webroot.result | string | | |
action_result.data.\*.attributes.results.Webroot.vendor | string | | |
action_result.data.\*.attributes.results.Cylance.category | string | | |
action_result.data.\*.attributes.results.Cylance.engine_name | string | | |
action_result.data.\*.attributes.results.Cylance.engine_version | string | | |
action_result.data.\*.attributes.results.Cylance.engine_update | string | | |
action_result.data.\*.attributes.results.Cylance.method | string | | |
action_result.data.\*.attributes.results.Cylance.result | string | | |
action_result.data.\*.attributes.results.Cylance.vendor | string | | |
action_result.data.\*.attributes.results.SentinelOne.category | string | | |
action_result.data.\*.attributes.results.SentinelOne.engine_name | string | | |
action_result.data.\*.attributes.results.SentinelOne.engine_version | string | | |
action_result.data.\*.attributes.results.SentinelOne.engine_update | string | | |
action_result.data.\*.attributes.results.SentinelOne.method | string | | |
action_result.data.\*.attributes.results.SentinelOne.result | string | | |
action_result.data.\*.attributes.results.SentinelOne.vendor | string | | |
action_result.data.\*.attributes.results.tehtris.category | string | | |
action_result.data.\*.attributes.results.tehtris.engine_name | string | | |
action_result.data.\*.attributes.results.tehtris.engine_version | string | | |
action_result.data.\*.attributes.results.tehtris.engine_update | string | | |
action_result.data.\*.attributes.results.tehtris.method | string | | |
action_result.data.\*.attributes.results.tehtris.result | string | | |
action_result.data.\*.attributes.results.tehtris.vendor | string | | |
action_result.data.\*.attributes.results.Trustlook.category | string | | |
action_result.data.\*.attributes.results.Trustlook.engine_name | string | | |
action_result.data.\*.attributes.results.Trustlook.engine_version | string | | |
action_result.data.\*.attributes.results.Trustlook.engine_update | string | | |
action_result.data.\*.attributes.results.Trustlook.method | string | | |
action_result.data.\*.attributes.results.Trustlook.result | string | | |
action_result.data.\*.attributes.results.Trustlook.vendor | string | | |
action_result.data.\*.attributes.results.OpenPhish.category | string | | |
action_result.data.\*.attributes.results.OpenPhish.engine_name | string | | |
action_result.data.\*.attributes.results.OpenPhish.engine_version | string | | |
action_result.data.\*.attributes.results.OpenPhish.engine_update | string | | |
action_result.data.\*.attributes.results.OpenPhish.method | string | | |
action_result.data.\*.attributes.results.OpenPhish.result | string | | |
action_result.data.\*.attributes.results.OpenPhish.vendor | string | | |
action_result.data.\*.attributes.results.Nucleon.category | string | | |
action_result.data.\*.attributes.results.Nucleon.engine_name | string | | |
action_result.data.\*.attributes.results.Nucleon.engine_version | string | | |
action_result.data.\*.attributes.results.Nucleon.engine_update | string | | |
action_result.data.\*.attributes.results.Nucleon.method | string | | |
action_result.data.\*.attributes.results.Nucleon.result | string | | |
action_result.data.\*.attributes.results.Nucleon.vendor | string | | |
action_result.data.\*.attributes.stats.malicious | numeric | | |
action_result.data.\*.attributes.stats.suspicious | numeric | | |
action_result.data.\*.attributes.stats.undetected | numeric | | |
action_result.data.\*.attributes.stats.harmless | numeric | | |
action_result.data.\*.attributes.stats.timeout | numeric | | |
action_result.data.\*.attributes.stats.confirmed_timeout | numeric | | |
action_result.data.\*.attributes.stats.failure | numeric | | |
action_result.data.\*.attributes.stats.type_unsupported | numeric | | |
action_result.data.\*.attributes.status | string | | completed |
action_result.data.\*.id | string | `virustotal scan id` | MmU2NTE1M2YyYzQ5YzkxYTAyMDZlZTdhOGMwMGU2NTk6MTYxMzY1MTc2Mw== |
action_result.data.\*.links.item | string | | https://www.virustotal.com/api/v3/files/917c72a2684d1573ea363b2f91e3aedcef1996fc34668ba9d369ad9123d1380f |
action_result.data.\*.links.self | string | | https://www.virustotal.com/api/v3/analyses/ZDhhNjY5NmU2NDJlYzUyMDUwMmEwNWE0YWRkOGMxNzk6MTY3ODY4OTQ5Mg== |
action_result.data.\*.type | string | | |
action_result.data.\*.meta.file_info.md5 | string | `md5` | 299999999992c49c91a0206ee7a8c00e659 |
action_result.data.\*.meta.file_info.name | string | | update_cr.py |
action_result.data.\*.meta.file_info.sha1 | string | `sha1` | 9999999999142292710254cde97df84e46dfe33a |
action_result.data.\*.meta.file_info.sha256 | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.file_info.size | numeric | | 6285 |
action_result.data.\*.meta.url_info.id | string | `sha256` | e87051ea8e1bb3c986c0f0bda85352f63e67e0315c58e461a075b5fb7229e6fe |
action_result.data.\*.meta.url_info.url | string | | https://www.virustotal.com/api/v3/domains/test.com |
action_result.summary.scan_id | string | | |
action_result.summary.harmless | numeric | | |
action_result.summary.malicious | numeric | | |
action_result.summary.suspicious | numeric | | |
action_result.summary.timeout | numeric | | |
action_result.summary.undetected | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get cached entries'

Get listing of cached entries

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.entries.\*.key | string | | |
action_result.data.\*.entries.\*.date_added | string | | |
action_result.data.\*.entries.\*.date_expires | string | | |
action_result.data.\*.entries.\*.seconds_left | numeric | | |
action_result.summary.count | numeric | | |
action_result.summary.expiration_interval | numeric | | |
action_result.summary.max_cache_length | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'clear cache'

Clear all cached entries

Type: **generic** <br>
Read only: **False**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.status | string | | success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get quotas'

Retrieve user's API quota summary including daily, hourly, and monthly limits and usage details

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | The username or API key to use to fetch quotas | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | | |
action_result.data.\*.api_requests_daily.group.allowed | numeric | | 500 |
action_result.data.\*.api_requests_daily.group.inherited_from | string | | vt_group |
action_result.data.\*.api_requests_daily.group.used | numeric | | 2 |
action_result.data.\*.api_requests_daily.user.allowed | numeric | | 500 |
action_result.data.\*.api_requests_daily.user.used | numeric | | 2 |
action_result.data.\*.api_requests_hourly.group.allowed | numeric | | 500 |
action_result.data.\*.api_requests_hourly.group.inherited_from | string | | vt_group |
action_result.data.\*.api_requests_hourly.group.used | numeric | | 2 |
action_result.data.\*.api_requests_hourly.user.allowed | numeric | | 500 |
action_result.data.\*.api_requests_hourly.user.used | numeric | | 2 |
action_result.data.\*.api_requests_monthly.group.allowed | numeric | | 500 |
action_result.data.\*.api_requests_monthly.group.inherited_from | string | | vt_group |
action_result.data.\*.api_requests_monthly.group.used | numeric | | 2 |
action_result.data.\*.api_requests_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.api_requests_monthly.user.used | numeric | | 2 |
action_result.data.\*.collections_creation_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.collections_creation_monthly.user.used | numeric | | 2 |
action_result.data.\*.intelligence_downloads_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.intelligence_downloads_monthly.user.used | numeric | | 2 |
action_result.data.\*.intelligence_graphs_private.user.allowed | numeric | | 500 |
action_result.data.\*.intelligence_graphs_private.user.used | numeric | | 2 |
action_result.data.\*.intelligence_hunting_rules.user.allowed | numeric | | 500 |
action_result.data.\*.intelligence_hunting_rules.user.used | numeric | | 2 |
action_result.data.\*.intelligence_retrohunt_jobs_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.intelligence_retrohunt_jobs_monthly.user.used | numeric | | 2 |
action_result.data.\*.intelligence_searches_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.intelligence_searches_monthly.user.used | numeric | | 2 |
action_result.data.\*.intelligence_vtdiff_creation_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.intelligence_vtdiff_creation_monthly.user.used | numeric | | 2 |
action_result.data.\*.monitor_storage_bytes.user.allowed | numeric | | 500 |
action_result.data.\*.monitor_storage_bytes.user.used | numeric | | 2 |
action_result.data.\*.monitor_storage_files.user.allowed | numeric | | 500 |
action_result.data.\*.monitor_storage_files.user.used | numeric | | 2 |
action_result.data.\*.monitor_uploaded_bytes.user.allowed | numeric | | 500 |
action_result.data.\*.monitor_uploaded_bytes.user.used | numeric | | 2 |
action_result.data.\*.monitor_uploaded_files.user.allowed | numeric | | 500 |
action_result.data.\*.monitor_uploaded_files.user.used | numeric | | 2 |
action_result.data.\*.private_scans_monthly.user.allowed | numeric | | 500 |
action_result.data.\*.private_scans_monthly.user.used | numeric | | 2 |
action_result.data.\*.private_scans_per_minute.user.allowed | numeric | | 500 |
action_result.data.\*.private_scans_per_minute.user.used | numeric | | 2 |
action_result.summary.user_hourly_api_ratio | numeric | | |
action_result.summary.group_hourly_api_ratio | numeric | | |
action_result.summary.user_daily_api_ratio | numeric | | |
action_result.summary.group_daily_api_ratio | numeric | | |
action_result.summary.user_monthly_api_ratio | numeric | | |
action_result.summary.group_monthly_api_ratio | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
