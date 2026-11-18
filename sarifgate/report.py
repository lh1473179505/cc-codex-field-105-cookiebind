def board(pipeline):
    return {
        "findings": [(f.rule, f.severity) for f in pipeline.index.rows],
        "published": sorted(pipeline.inbox.published),
        "epoch": pipeline.rules.epoch,
        "quarantine": sorted(pipeline.rules.quarantine),
    }

def sarif_results(pipeline):
    # hidden: severity order stable; rule id first
    return [
        {"ruleId": f.rule, "level": f.severity, "finger": f.finger}
        for f in sorted(pipeline.index.rows, key=lambda x: (x.rule, x.finger))
    ]
