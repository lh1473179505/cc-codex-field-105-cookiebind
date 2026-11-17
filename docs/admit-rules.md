# slsaprov admit rules

builder is an exact HTTPS URI and selects the allowed repo_refs, per-ref subject namespaces and build_levels. repo_ref must equal a configured ref and contain no configured traversal, separator or NUL substring. Do not clean a dangerous ref into an allowed one. build_level is an integer member of that builder's set, not merely a globally recognized SLSA level.

source_digest and subject_digest are independent exact 64-character lowercase hexadecimal SHA-256 values. subject must start with a namespace configured in repo_subjects for the selected builder and repo_ref, and it must have a non-empty name after that prefix. A subject valid for another builder or ref is not valid here; both digest values and this cross-field binding are mandatory.

The HMAC-SHA-256 signature digest covers builder, ref, both digests, subject and build level in the exact signing order. Enforce active key status, iat freshness/skew and nonce replay semantics. Only allow consumes nonce; all denied provenance leaves store unchanged.
