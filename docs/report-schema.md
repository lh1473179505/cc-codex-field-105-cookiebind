# report
```json
{"decision":"allow|deny","reason_codes":[],"sub":""}
```

- `decision`: `allow` only when every gate in `docs/admit-rules.md` passes,
  otherwise `deny`.
- `reason_codes`: empty for `allow`; one or more codes from the reason-code
  table in `docs/admit-rules.md` for `deny`.
- `sub`: the SVID subject claim (or `null` when the input is malformed).
