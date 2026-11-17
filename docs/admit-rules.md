# dmarcagg admit rules

domain selects the allowed org strings, report_id prefixes, source networks and exact report window. org must match exactly and report_id must begin with a configured prefix followed by a non-empty suffix. begin/end are integer Unix seconds with begin < end and end - begin == window_seconds; timestamp freshness is separate from the report's historical range.

Each records item has exact ASCII form `source_ip|count|spf|dkim`. source_ip must parse as an IP address inside a domain source_cidrs network and must be unique across records; count is a positive base-10 integer without signs or leading zeroes. spf and dkim are members of their respective result sets. When require_any_aligned is true, every record must have at least one of SPF or DKIM equal to pass. Enforce inclusive record count bounds.

total_count must equal the arithmetic sum of all record counts, and report_sha256 must be exactly 64 lowercase hexadecimal characters. Sign the ordered record strings and every range/count field using the HMAC-SHA-256 contract. Apply revocation, iat skew/freshness and nonce replay checks; deny never writes store.
