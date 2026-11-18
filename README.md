# trivyconf

Offline `trivyconf` scan convergence service. It models a real incremental writer,
an authoritative full-snapshot writer, revocation/recovery, a fingerprint index,
and two read-only consumers. Only the Python standard library is required.

Run the integrated baseline reproducer:

```console
python reproduce.py
```

Run the independent CLI batch or audit chain:

```console
python -m trivyconf run fixtures/combination.json
python -m trivyconf audit fixtures/combination.json
```

Run the repository tests with `python -m unittest discover -s tests -v`.
The combination tests assert cross-phase convergence (snapshot authority,
target-isolated cache reuse, revocation recovery, late-retransmission
rejection) together with the read-only compatibility guarantees.
