def audit_blob(store, hooks, operation):
    lease = hooks.inflight[operation]
    # Old consumers inspect the borrowed bytes after the update call returns.
    return {"operation": operation, "namespace": lease["namespace"],
            "decision": bytes(lease["view"]).decode("ascii"),
            "phase": store.phase[lease["name"]]}
