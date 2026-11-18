# sqsqueue admit rules

queue_arn is an exact policy key. account_id and resource_arn must exactly equal that queue's values, including account, region and queue name embedded in the ARN. actions is an ordered array of unique exact SQS action strings, a subset of actions_allowed and a superset of actions_required; wildcards and cross-queue actions are invalid.

conditions is a string-valued object. Its keys are restricted to conditions_allowed and every conditions_required key/value pair must be present exactly. SourceAccount from another queue cannot replace the selected queue's required VPC or SecureTransport conditions. encryption must be exactly the configured object with both the KMS alias and sse_enabled boolean equal to policy.

Action order, recursively sorted condition and encryption keys, and all other fields are authenticated in the declared sequence. HMAC key status, 600-second iat age, 60-second future skew and nonce freshness are separate gates. A denial never consumes nonce or writes store.
