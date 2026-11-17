# bpfload admit rules

prog_type must select policy.programs and must not occur in forbidden_prog_types, even when its own entry otherwise matches. attach_type and license belong to that program's lists. insn_count is an integer in the inclusive program-specific insn_min/insn_max range.

Every map_refs item must occur in map_registry and in the selected program's maps. The list is unique and its length cannot exceed map_refs_max. privileged must be 0 whenever forbid_privileged is true; no valid program, attach type or license overrides that prohibition. All fields participate in HMAC, with revoked-key and iat-window denial and nonce consumption only after allow. Deny does not save store.
