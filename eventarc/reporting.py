def channel_report(triggers):
    return {"rows": list(triggers.sink.rows),
            "positions": dict(triggers.watermarks.positions),
            "handled": sorted(triggers.dispatcher.handled)}
