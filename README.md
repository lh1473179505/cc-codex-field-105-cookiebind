# relreqx

Offline related-request policy engine for CC Codex.

`admit` evaluates the interacting gates documented in
[docs/admit-rules.md](docs/admit-rules.md) (HMAC signature, key
revocation, schemeful same-site isolation, cors/navigate mode rules,
destination binding, null origin, http downgrade, host case and replay)
and emits the report shape from [docs/report-schema.md](docs/report-schema.md).

CLI:

```sh
python -m relreqx inspect --input fixtures/cases/ok-same/input.json
python -m relreqx admit --input fixtures/cases/ok-same/input.json \
  --keys fixtures/keys.json --policy fixtures/policy.json \
  --store /tmp/store.json --now 2026-06-18T12:00:00Z \
  --report /tmp/report.json
```

Library:

```python
from relreqx.engine import admit_object
report = admit_object(obj, keys, policy, store, now_unix)
```

Exit codes: allow `0`, deny `1`, load failure `2`. A deny never writes
the store; only an allow records the request id. Run the suite with
`python -m unittest discover -s tests`.
