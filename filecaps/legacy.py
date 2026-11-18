def audit_snapshot(store):
    # Version 1 consumers require these keys and a side-effect-free read.
    return {"outcomes": [{"id": p["id"], "outcome": p["status"]}
                         for p in store.data["journal"]],
            "nodes": {name: {"permitted": list(node["permitted"]),
                             "effective": list(node["effective"])}
                      for name, node in store.data["nodes"].items()}}
