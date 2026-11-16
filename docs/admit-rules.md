# sftpupld admit rules

Select the user, require root to equal that user's root, then validate path as a relative slash-separated name. Reject absolute paths and every configured unsafe substring before prefix checks. Do not normalize a dangerous path into an allowed one. path must start with a user path_prefix and contain no empty, `.` or `..` component.

size is an integer from size_min through the user's size_max. mode must be one of that user's exact four-digit strings. sha256 is exactly 64 lowercase hex characters. All these fields are signed. Apply key status and iat rules; record nonce only for an allow decision and never save store for deny.
