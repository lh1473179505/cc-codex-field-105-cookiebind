# Provenance attestation compatibility
Drafted artifacts must be re-checked against role revocation before the first seal
write. `legacy_digests` is a flat list consumed by an older verifier. `prov-1`
checkpoints omit drafts; `granted` means sealed successfully.
