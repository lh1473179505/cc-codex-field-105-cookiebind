from sseauth.audit import view
from sseauth.events import Event
from sseauth.feed import Client, Feed
from sseauth.tokens import Tokens

def scenario():
    tokens = Tokens()
    token = tokens.issue(1)
    client = Client(fail={"new"})
    feed = Feed(client, tokens)
    events = [Event("e2", 2, 1, "new"), Event("e1", 1, 1, "old")]
    try:
        feed.subscribe(token, events)
    except OSError:
        pass
    tokens.revoke(1)
    client.fail.clear()
    feed.subscribe(token, events)
    state = feed.snapshot()
    resumed = Feed(Client(), tokens)
    resumed.restore(state)
    return view(feed), view(resumed)

if __name__ == "__main__":
    original, resumed = scenario()
    assert original["rows"] == [("e1", "old")]
    assert original["last_sequence"] == 2
    assert resumed["sent"] == ["e1", "e2"]
    print("reproduced: failed SSE send advanced resume past both events", original)
