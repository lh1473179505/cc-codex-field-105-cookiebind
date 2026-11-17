# landlockx admit rules

abi is an integer key into abi_access and must also lie within the selected allowed_path entry's abi_min/abi_max. access_fs is a unique, nonempty subset of both the ABI rights and that path's access_allowed. allowed_path must exactly select a policy.paths entry; rights supported by another ABI or path do not count.

Every beneath item is a unique relative slash-separated path with no empty, `.` or `..` component, backslash, NUL or absolute prefix. Enforce beneath_min and the selected path's beneath_max. read_write is 0 or 1. With read_write=1, access_fs contains read_file and write_file and every beneath path starts with an rw_prefix. With read_write=0, write_file/remove_file/refer/truncate are forbidden and every beneath path starts with an ro_prefix. The signed line includes all rights and paths; key status, iat and nonce semantics are mandatory and deny never writes store.
