# gcpiambind admit rules

Look up project and role within that project. When forbid_owner is true, roles/owner is denied independently of all other checks. principal must be `user:mailbox`, `group:mailbox` or `serviceAccount:mailbox`; public principals are forbidden. User/group domains must belong to member_domains, while service accounts use exactly `<name>@<project>.iam.gserviceaccount.com` with project in service_account_projects. The principal scheme must also occur in role_principals for the selected role.

A condition is either empty or an object with exactly title and expression. Roles in required_condition_roles need a nonempty condition whose title occurs in conditions and whose expression exactly equals the configured expression. Roles in empty_condition_roles require `{}`. Do not accept a syntactically valid but unapproved expression.

Verify HMAC over the exact `v1|` line in parts order, sorting condition keys as `key=value`. Enforce key status, clock_skew_seconds/max_age_seconds and nonce consumption only on allow; deny leaves store unchanged.
