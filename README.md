# semgrepr

Offline `semgrepr` scan convergence service. It models a real incremental writer,
an authoritative full-snapshot writer, revocation/recovery, a fingerprint index,
and two read-only consumers. Only the Python standard library is required.

Run the integrated baseline reproducer:

```console
python reproduce.py
```

Run the independent CLI batch or audit chain:

```console
python -m semgrepr run fixtures/combination.json
python -m semgrepr audit fixtures/combination.json
```

Run the repository tests with `python -m unittest discover -s tests -v`.
The combination test covers the cross-phase convergence of snapshot, delta,
revocation and recovery alongside the read-only compatibility assertions.
