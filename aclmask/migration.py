from . import lifecycle

def begin_move(repo, path, destination):
    obj = repo.state["objects"][path]
    obj["namespace"] = destination
    repo.state["aliases"][path] = (destination, lifecycle.MIGRATING)
    repo.flush()
    return repo.state["aliases"][path]

def finish_move(repo, path):
    repo.state["aliases"][path] = (repo.state["objects"][path]["namespace"], "settled")
    repo.flush()
