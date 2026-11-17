# spdxrel admit rules

Select `documents[document_namespace]`; all element resolution remains inside that document. Both IDs must match `spdx_id_pattern` and exist in `elements`. `spdx_id` and `related_spdx_id` must differ. Namespace or element registration in another SPDX document grants no validity here.

Look up `relationships[spdx_id][relationship_type]` and require `related_spdx_id` in its target list. A globally known relationship name is insufficient when that source/type/target triple is unregistered.

`license` must exactly equal `elements[related_spdx_id].license`. If the target kind is `File`, `file_sha256` must be exactly 64 lowercase hexadecimal characters and equal that element's `sha256`. For every non-File target, `file_sha256` must be empty; never copy a file digest onto a Package or Document.

The exact signing line includes namespace, both IDs, relation, license and digest. Enforce active-key HMAC, iat age/skew and replay state; denied relationships leave store untouched.
