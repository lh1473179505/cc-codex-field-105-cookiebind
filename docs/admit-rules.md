# tacacsx admit rules

Authorization is resolved through group -> service -> command. user must be a member of the selected group, and names are case-sensitive exact strings. Membership of a command in another group or service has no bearing on the selected path.

args is an ordered JSON array of strings. The complete array must equal one entry in the command's argument_sets, including order, item count and empty-array behavior; joining arguments into a shell-like command is not equivalent. priv_lvl is a JSON integer and must be a member of that command's priv_lvls.

The ordered args array is comma-joined in the signing line along with every other declared field. HMAC verification, active-key status, iat freshness/skew and allow-only nonce consumption are mandatory. Denied commands never modify store.
