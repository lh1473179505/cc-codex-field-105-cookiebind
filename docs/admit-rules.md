# flowrec admit rules

Select `exporters[exporter]`. Parse `src_ip` and `dst_ip` as IP addresses, not CIDR networks, and require containment in at least one same-side CIDR from that exporter. Do not use textual prefixes or another exporter's networks. Both ports are integers in inclusive `port_min..port_max`.

`protocol` must belong to the exporter's `protocols`; `dst_port` must then occur in `dst_ports[protocol]`. Thus a port allowed for UDP is not automatically valid for TCP. `packets` and `bytes` are integers within their respective inclusive exporter bounds, and `bytes >= packets * min_bytes_per_packet` is mandatory.

`start_time` and `end_time` are integer Unix seconds with `start_time >= start_time_min`, `start_time <= end_time`, and `end_time - start_time <= duration_max`. Zero duration is valid; negative or excessive duration is not.

All tuple, counter and time fields occur in the signing line. Enforce HMAC key status, iat age/skew and replay protection, writing nonce/store only for a final allow.
