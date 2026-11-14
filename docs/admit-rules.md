# k8sadmit admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{ns}|{sa}|{images_csv}|{priv}|{caps_csv}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 镜像必须在 allow_repos 且带 digest
- privileged=true 拒绝；hostPath 路径前缀拒绝
- capabilities.add 不得包含 denied_caps
- ns/sa 绑定；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-web, ok-job

Deny cases: bad-sig, image, priv, hostpath, cap, ns, revoked, tag-only

Reason codes should be stable snake_case identifiers matching the failing gate.
