# cwegraph admit rules

`cve` must match `cve_pattern` and select a CVE entry. `cwe_id` must match `cwe_pattern`, exist in the global `cwes` catalog, and occur beneath that CVE's `cwes`; global existence alone never authorizes a CVE mapping. `relation` must belong to the selected CVE/CWE pair's relations.

`evidence` is a unique, case-sensitive string list with inclusive size `evidence_count_min..evidence_count_max`. Every item must belong to the global CWE's `evidence_allowed`, and the list must contain every `required_evidence` item from the CVE/CWE mapping. Do not substitute evidence allowed for a different weakness.

`confidence` is a JSON integer, not a boolean or string, in inclusive `confidence_min..confidence_max`. Whenever confidence is at least `high_confidence_min`, every `high_confidence_evidence` item must also be present. A high score cannot compensate for missing corroboration.

Preserve evidence order in the exact signing line. Verify complete HMAC-SHA-256, active key status and iat age/skew; consume nonce only after every gate allows. All denials leave store unchanged.
