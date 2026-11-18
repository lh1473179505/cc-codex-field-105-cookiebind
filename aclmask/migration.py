from . import lifecycle

def begin_move(repo, path, destination):
    # The object keeps its original namespace while migrating so that legacy
    # diagnostics keyed by the original path keep seeing the same boundary.
    # New requests are gated by the target namespace generation instead.
    repo.state["generation"] += 1
    repo.state["aliases"][path] = (destination, lifecycle.MIGRATING)
    repo.flush()
    return repo.state["aliases"][path]

def finish_move(repo, path):
    destination = repo.state["aliases"][path][0]
    repo.state["objects"][path]["namespace"] = destination
    repo.state["aliases"][path] = (destination, "settled")
    repo.flush()
