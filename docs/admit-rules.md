# ptracex admit rules

Resolve caller -> target -> target policy. Both identities are exact case-sensitive names; a target known to another caller is not authorized. scope must be a member of that target's scopes, so process, thread and thread-group are distinct rather than aliases. The caller/target relationship represents the permitted Yama relation and cannot be replaced by a global debugger flag.

capability is an exact member of the selected target's capabilities. `none` and `CAP_SYS_PTRACE` are not interchangeable across callers. dumpable is a JSON boolean exactly equal to the target requirement; integer zero and one are not booleans. yama is a JSON integer, excluding booleans and strings, and must be a member of that target's yama_values.

A capability valid elsewhere never overrides a failed target, dumpable or Yama gate. Sign the complete caller/target/scope/capability/dumpable/yama sequence. Require valid HMAC, active key, fresh iat and unused nonce; denied traces do not consume nonce or modify store.
