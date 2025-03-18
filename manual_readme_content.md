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
