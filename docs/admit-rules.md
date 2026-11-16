# scepenrl admit rules

The profile controls CN suffix, every dns_names suffix, key algorithm/size, usage and challenge. Names are exact lowercase DNS names with one non-empty label before an allowed suffix; do not accept a suffix lookalike. dns_names are unique and limited to max_dns_names. When require_cn_in_dns is true, CN must occur literally in dns_names.

key_usage must contain required_usage and be a subset of allowed_usage. key_alg/key_bits must be an allowed pair for the profile. challenge starts with a profile prefix and meets challenge_min_len. Validate the exact signed line, active key, iat and nonce; denied requests do not mutate store.
