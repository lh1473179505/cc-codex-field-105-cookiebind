# fanotify admit rules

mount is a canonical absolute mount policy key. path is also canonical and absolute, must be strictly beneath that mount on a real slash boundary, and its first relative component must occur in the mount's path_components. Reject lookalike prefixes, empty components, repeated slashes, backslashes, NUL and `.`/`..`; never normalize a dangerous path into an allowed mark.

event_mask and flags are ordered lists of unique strings. Each list must be a subset of its mount's allowed set and contain every required item. permission is an exact member of the mount permissions and must itself occur in event_mask. An event or flag valid on another mount has no effect here, and permission events cannot be smuggled in as unrelated notification bits.

The supplied event-mask and flag order is preserved by the signing line along with mount, path and permission. Enforce HMAC-SHA-256, key status, iat freshness/skew and replay detection. Only allow records the nonce and saves store; all denied marks leave both unchanged.
