# OCI index publication

Index updates are copy-on-write transactions. A staged descriptor can
have a content blob but remains absent from `index.json` until the
entire platform batch seals. Abort and recovery compaction preserve
the previously visible ordered descriptor array.

Legacy lookup returns only `digest` and `size`; platform variant is
significant during lookup even though it is absent from that result.
Single-descriptor publication and complete index import share the same
atomic boundary, and duplicate platform descriptors are not silently
used as transaction markers.
