def legacy_monitor(groups):
    return {"events": [{"name": name, "running": item["state"] == "armed",
                        "cpus": list(item["cpus"]), "cgroup": item["cgroup"]}
                       for name, item in groups.items.items()]}
