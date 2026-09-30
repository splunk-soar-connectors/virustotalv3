**Unreleased**

* Use Jinja-compatible JSON escaping for values in widget context menus.
* Fixed get report failing after a completed analysis was returned.
* Persist request rate-limit timestamps and report VirusTotal quota errors instead of treating them as empty lookups.
* Use completed analysis data and the original submitted URL or file hash in detonation outputs and widgets.
