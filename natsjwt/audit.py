def inspect(service):
    """Legacy read-only view consumed by operations dashboards."""
    return {
        "values": list(service.sink.values),
        "offset": service.checkpoint.offset,
        "pending": sorted(service.window.pending),
        "seen": sorted(service.window.seen),
    }
