# apparmor admit rules

Select policy.profiles[name] and require path to equal that profile's path. Each rules item has the exact form `absolute-path permissions,`: one space, a nonempty permission string drawn from the profile permissions, and one trailing comma. Rule paths contain no path_deny_substrings, empty component, `.` or `..`; each must begin with a profile path_prefix. Do not clean a rejected path into an allowed one.

The rules list is unique and its size is within rule_count_min/rule_count_max. mode must equal the profile mode. capabilities and network are unique lists and subsets of the corresponding profile lists; an empty capability list is valid only where the profile allows no capabilities. HMAC covers every field in signing order, with active-key, iat-window and allow-only nonce consumption requirements. Denials leave store unchanged.
