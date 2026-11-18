# nucleix

Offline `nucleix` scan convergence service. It models a real incremental writer,
an authoritative full-snapshot writer, revocation/recovery, a fingerprint index,
and two read-only consumers. Only the Python standard library is required.

Run the integrated baseline reproducer:

```console
python reproduce.py
```

Run the independent CLI batch or audit chain:

```console
python -m nucleix run fixtures/combination.json
python -m nucleix audit fixtures/combination.json
```

Run the repository tests with `python -m unittest discover -s tests -v`.
The combination tests assert that snapshot recovery, late retransmissions and
repeated read-only report/audit consumption all converge without mutating
scan state.
