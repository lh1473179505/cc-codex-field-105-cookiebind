# jarmanif admit rules

## Signing input
`v1|{kid}|{main_class}|{impl_title}|{sealing}|{path=sha256,...}|{required_csv}|{svc_line}|{alg}|{total_size}|{created}|{nonce}`

Entry `sha256` = `SHA256(utf8(path)||0x00||content)`. `body_sha256[path]` = `SHA256(content)` only.

## Path safety (before prefix allow)
Reject if any path contains path_deny_substrings OR (forbid_absolute and path startswith `/`).
If forbid_duplicate_paths: paths must be unique.

## Main binding
main_class ∈ mains. impl_title/sealing/svc_line must equal mains[main_class].*.

## Required files
Every name in required_files_all must appear in entries paths. required_files field in input must equal required_files_all (order may follow fixture).

## Body / size / alg
If require_body_sha_match: for each entry, body_sha256[path] present and SHA256(path||0x00||content_implied) consistency:
practical fixture rule — entry.sha256 must equal SHA256(path||0x00||X) where SHA256(X)==body_sha256[path]; else body_mismatch.
Each entry.size <= max_entry_size; total_size <= max_total_size and total_size == sum(entry.size).
alg ∈ allowed_algs.

## Time / store
created within max_age; HMAC + kid_revoked; nonce allow-only write.
