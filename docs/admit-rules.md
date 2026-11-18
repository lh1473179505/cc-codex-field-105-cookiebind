# snsdeliv admit rules

topic_arn selects one topic, principal must be registered beneath it, and protocol then selects one subscription profile. ARN partition, region, account, resource and role text are compared exactly. endpoint must equal one of that protocol profile's endpoints; an endpoint valid for another protocol or topic is not accepted.

raw_message_delivery is a JSON boolean exactly equal to the subscription requirement. filter_policy is an object exactly equal to the configured filter map: keys must match, every value is a string array, and array order is significant. Adding a valid filter from another protocol or dropping a required filter is denied.

All nested filter keys and ordered values participate in the complete HMAC representation, as do endpoint and raw mode. The signing key must be active, iat must be within 600 seconds of age and 60 seconds of future skew, and nonce must be new. Only allow records nonce and saves store.
