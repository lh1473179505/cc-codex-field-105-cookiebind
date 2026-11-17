# mtasts

MTA-STS policy admission with policy ID/domain, mode, MX suffixes, max_age and report-domain alignment.

## admit

```sh
python -m mtasts admit --mta-policy <policy.json> --keys <keys.json> \
  --policy <constraints.json> --store <store.json> --now <unix|ISO8601> --report <out.json>
```

The CLI and `mtasts.admit_policy.admit_policy` (re-exported as `mtasts.engine.admit_policy`)
share one decision function. Exit code is `0` for allow, `1` for deny and `2` for malformed
inputs. The store is rewritten only on allow; a deny never consumes the nonce or mutates state.

### signing input

```
v1|{kid}|{policy_id}|{domain}|{mode}|{mx}|{max_age}|{report_domain}|{policy_sha256}|{iat}|{nonce}
```

`{mx}` is the ordered MX list joined with commas. The key secret is hex-decoded and the
HMAC-SHA-256 digest is emitted as unpadded base64url.

### reason codes

- `unknown_domain`, `policy_id_not_allowed`, `mode_not_allowed`, `report_domain_misaligned`
- `policy_sha256_bad_format` (exactly 64 lowercase hex characters)
- `mx_shape_invalid`, `mx_count_out_of_range`, `mx_not_unique`, `mx_host_not_lowercase`
- `mx_suffix_violation`, `mx_required_missing`
- `max_age_out_of_range` (inclusive per-domain bounds)
- `unknown_kid`, `key_revoked`, `bad_signature`
- `iat_outside_window` (`now - max_age_seconds <= iat <= now + clock_skew_seconds`)
- `nonce_invalid`, `nonce_replay`
