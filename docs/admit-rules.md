# rrsigoff admit rules

Offline DNSSEC-like RRSIG over a canonical RRSET.

## RRSET canonicalization

Sort RRs by `rdata` ascending; each line `name|type|class|ttl|rdata`.
`cover = sha256(canonical bytes).hexdigest()`.

## Signing line

`v1|{kid}|{signer}|{type_covered}|{labels}|{orig_ttl}|{inception}|{expiration}|{cover}|{nonce}`

## Gates

1. HMAC + kid revoke; key.signer must equal answer.signer when present in key record.
2. signer in allowed_signers; type_covered in allowed_types and equals every RR type if require_uniform_name_type.
3. Every RR name endswith require_rrset_name_suffix; all names equal when uniform.
4. now in [inception-skew, expiration+skew].
5. labels <= max_labels.
6. If nsec present with claims_nxdomain_for: owner/next must form an interval that **covers** the claim name in canonical DNS order **and** claim name must not exist as an RRSET name — fixtures deny-nsec-lie claims nxdomain for www while proving unrelated a→b interval => `nsec_lie`.
7. nonce replay; write only allow.
