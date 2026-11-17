# jitaccess admit rules

Select user and require resource in that user's resource list, then select role beneath the resource. duration must be within that role's inclusive bounds. ticket must match ticket_pattern and begin with the role ticket_prefix. A ticket valid for another resource or role is not interchangeable.

approval is an object with exactly approver and decision. approver must belong to the role approvers and decision must be in approval_decisions. When forbid_self_approval is true, approver must differ from user even if the user is listed as an approver.

Verify HMAC over the exact `v1|` line in parts order with approval rendered as sorted `key=value` pairs. Enforce key status, clock_skew_seconds/max_age_seconds and nonce consumption on allow only. Denials leave store unchanged.
