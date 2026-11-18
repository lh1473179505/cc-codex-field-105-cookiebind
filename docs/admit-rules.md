# jsonnetx admit rules

Select `entries[entry]` by exact relative entry path. `imports` is an ordered, unique string list with inclusive size `import_count_min..import_count_max`, a subset of `imports_allowed` and a superset of `imports_required`. Each import is a relative path ending in `import_suffix`, with no absolute prefix, empty/`.`/`..` component or `path_deny_substrings`; never resolve an unsafe import through filesystem cleaning.

`ext_vars` must exactly equal the selected entry's registered key/value mapping. Extra variables are denied even if their values appear harmless, and no external code string or host variable is merged. `output_path` is a safe relative path exactly equal to the registered output, not a caller-selected sibling or traversal target.

`libraries` is an ordered, unique list and a subset of `libraries_allowed`. Its set must exactly equal the set obtained by mapping every selected import through `import_libraries`; therefore a missing required library and an unused extra library both fail. Import order and library declaration order remain significant for signing even though closure uses sets.

Sign entry, imports, sorted ext_var key/value pairs, output and libraries in declared order. Enforce active-key HMAC, iat age/skew and replay protection, consuming nonce/store only after allow. Every deny leaves store unchanged.
