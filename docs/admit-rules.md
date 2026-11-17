# wasipre admit rules

module selects exactly one policy.modules entry and preopen must equal that entry's preopen string. path is a relative slash-separated name beneath one path_prefix. Reject absolute paths and every path_deny_substrings match, including encoded traversal; also reject empty, `.` and `..` components. No decoding or normalization may turn an unsafe path into an accepted one.

read and write are integers in permission_values, and at least one must be 1. read=1 requires read_allowed. write=1 requires write_allowed and a path beneath one write_prefix; module-level write permission does not make every path writable. All fields are signed in the declared order. Apply key revocation, iat freshness and nonce replay checks, with no store write for deny.
