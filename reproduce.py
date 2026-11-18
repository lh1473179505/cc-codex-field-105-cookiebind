from eventarc.records import Record
from eventarc.reporting import channel_report
from eventarc.triggers import Triggers

def scenario():
    triggers = Triggers(fail={"second"})
    late = Record("one", "news", 1, False, "first")
    closing = Record("two", "news", 2, True, "second")
    try:
        triggers.ingest(closing)
    except RuntimeError:
        pass
    triggers.sink.fail.clear()
    triggers.ingest(late)
    triggers.ingest(closing)
    snapshot = triggers.snapshot()
    restored = Triggers()
    restored.recover(snapshot, [late, closing])
    return channel_report(triggers), channel_report(restored)

if __name__ == "__main__":
    original, restored = scenario()
    assert original["rows"] == []
    assert original["positions"] == {"news": 2}
    assert restored["handled"] == ["two"]
    print("reproduced: trigger watermark and handled set outran durable dispatch", original)
