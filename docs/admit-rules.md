# osquery admit rules

Traverse `packs[pack].queries[query_name]`; a query known only under another pack is invalid. `sql` is one non-empty read-only SELECT statement with length at most `sql_length_max`. Reject every token in `sql_deny_tokens`, including statement separators and comment markers, rather than stripping them. No write, schema, pragma or attach operation is accepted.

Every entry in `tables` is a unique lowercase identifier matching `identifier_pattern`; list size is inclusive `table_count_min..table_count_max`. The declared set must be a subset of the selected query's `tables` and exactly equal the set of table identifiers referenced by SQL FROM/JOIN clauses. Neither an omitted SQL table nor an undeclared extra table is valid.

`interval` must exactly belong to the query's `intervals`, and `platform` must belong to its `platforms`. Do not approximate an interval or borrow another query's platform. Preserve table order in the signing line. Apply HMAC, revocation, iat freshness and allow-only nonce consumption; deny never persists store.
