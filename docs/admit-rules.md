# kustomizex admit rules

Select `overlays[overlay]`; all paths and namespace values are resolved only under that overlay. `base_path` is a relative canonical path exactly equal to the registered base. It must not contain path_deny_substrings, empty components, `.` or `..`; do not clean an unsafe path before comparison.

`resources` and `patches` are ordered, unique string lists that must exactly equal the selected overlay's registered lists, including the base resource as the first resources entry. Missing, extra, reordered or duplicate entries are invalid. Every contained path is also subject to the same relative-path safety gates, so an unsafe item cannot hide inside an otherwise valid list.

`namespace` exactly equals the overlay namespace and cannot be default or another environment. `secret_fields` must exactly equal the registered empty list. Every `forbidden_secret_fields` item is denied, including secretGenerator and literal/file/env sources; no generator, inline secret or source field is silently ignored.

Preserve resources, patches and secret_fields order in the signing line together with base and namespace. Verify active-key HMAC, iat age/skew and replay status. Consume nonce and save store only for allow; every deny leaves store unchanged.
