# Delivery notes
The dashboard's `values`, `offset`, `pending`, and `seen` fields are a stable,
read-only diagnostic view. A retry of an event key must not produce a second
delivery, but a failed sink write has not been delivered. Recovery may receive
both a snapshot and an unordered tail; snapshot version 1 remains supported.
A barrier includes every sequence below it, including sequences arriving later.
