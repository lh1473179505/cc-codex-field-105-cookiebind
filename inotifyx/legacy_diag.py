def snapshot(watches, queue):
    # Historic diagnostics include pending events for a text report.
    pending = queue.read_all()
    return {"watches": [{"wd": wd, "path": item["path"], "state": item["state"]}
                        for wd, item in watches.by_wd.items()],
            "pending": [{"kind": event["kind"]} for event in pending],
            "dropped": queue.dropped}
