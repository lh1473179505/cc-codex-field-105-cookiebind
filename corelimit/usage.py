def legacy_usage(vault):
    return {"used_bytes": vault.data["used"], "limit_bytes": vault.data["limit"],
            "reservations": dict(vault.data["reserved"]),
            "states": {key: value["phase"] for key, value in vault.data["captures"].items()}}
