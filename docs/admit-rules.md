# jailparam admit rules

name is at most name_max_len characters and matches `[a-z][a-z0-9_-]*` before selecting policy.jails[name]. jid and securelevel are integers, not booleans. jid is within jid_min/jid_max and equals the selected jail's jid. hostname is an exact lowercase DNS name equal to the jail hostname.

Parse ip4 as a plain IPv4 address, with no prefix or zone; reject forbidden_ip4, multicast and loopback addresses, then require membership in one of the jail's ip4_networks. path is an absolute canonical path without path_deny_substrings or empty/`.`/`..` components and must exactly equal the jail path. securelevel is inclusive within the jail's min/max. The complete signed line, key status, iat and nonce replay checks apply; deny leaves store unchanged.
