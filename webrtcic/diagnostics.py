def routes(session):
    return {"generation": session.description.generation,
            "routes": list(session.transport.routes),
            "applied": sorted(session.pool.applied)}
