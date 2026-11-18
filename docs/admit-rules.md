# ocilayout admit rules

Select `images[image_ref]` using the complete case-sensitive registry/repository/tag string. `digest` is the image index digest in exact `sha256:` plus `digest_hex_length` lowercase hexadecimal form and must equal the selected image's registered digest. Do not confuse this parent digest with a child manifest digest.

`manifest` uses the same strict digest syntax and must identify one entry in that image's `manifests` list. A manifest registered under another image is invalid. Once the manifest entry is selected, `media_type` must exactly equal that entry's media type; a Docker media type or an OCI index media type cannot replace the declared image-manifest type.

`platform` is an object with exactly `platform_keys` and exact `os`, `architecture` and `variant` values from that same manifest. Empty variant is significant for amd64, arm64 requires its registered v8 variant here, and extra platform keys are invalid. The platform cannot be used to select a different manifest after digest validation.

The signing line includes both digest layers, media type and sorted platform key/value pairs. Apply active-key HMAC, iat freshness/skew and replay protection before allow-only nonce/store persistence. Denied imports never mutate store.
