def lookup(sessions, namespace, pid):
    sid = sessions.registry.resolve(namespace, pid)
    return None if sid is None else sessions.items[sid]
