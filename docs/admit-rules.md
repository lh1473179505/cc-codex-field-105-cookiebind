# pidnsjoin admit rules

caller must select policy.callers and target must exist in namespace_inodes and in that caller's targets. Membership does not override forbidden_targets. When forbid_self_join is true, caller and target must differ even if self occurs in targets.

ns_inode is an integer at least ns_inode_min and exactly equals namespace_inodes[target]; another valid namespace inode is not accepted. fd_type must belong to both the global fd_types and caller fd_types. capability must belong to global capabilities and equal the caller required_capability. The signature covers all identity and numeric fields. Reject revoked keys, stale/future iat and replayed nonces; only allow writes store.
