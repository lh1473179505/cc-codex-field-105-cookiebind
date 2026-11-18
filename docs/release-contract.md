# Role epochs and snapshot consumers

A prepared role transaction captures the signing epoch when it begins.
Rotating root keys affects new transactions, while already prepared work
retains the permission and signature context it captured. Online commit
and restart recovery therefore use the same context.

Envelope version 1 authenticates only role and version. Its snapshot
representation remains `{"format": 1, "roles": {name: {"version": n}}}`.
Newer envelopes may authenticate epochs without changing this reader.
A failed recovery leaves the prior snapshot readable and retryable.
