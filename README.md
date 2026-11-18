# gitleaksr

Offline `gitleaksr` scan convergence service. It models a real incremental writer,
an authoritative full-snapshot writer, revocation/recovery, a fingerprint index,
and two read-only consumers. Only the Python standard library is required.

Run the integrated baseline reproducer:

```console
python reproduce.py
```

Run the independent CLI batch or audit chain:

```console
python -m gitleaksr run fixtures/combination.json
python -m gitleaksr audit fixtures/combination.json
```

Run the repository tests with `python -m unittest discover -s tests -v`.
The combination tests assert that snapshot and incremental writers share one
progress boundary, so a late retransmission cannot cross a newer recovery,
alongside the read-only compatibility assertions.
