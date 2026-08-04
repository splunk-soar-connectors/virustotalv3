**Unreleased**

* Validate and encode IP reputation inputs before placing them in VirusTotal API paths.
* Track rate-limit requests with numeric local timestamps and prevent negative wait durations.
* Limit detonation and report initial wait durations to 900 seconds.
* Return a controlled action failure when VirusTotal sends an unexpected JSON response shape.
