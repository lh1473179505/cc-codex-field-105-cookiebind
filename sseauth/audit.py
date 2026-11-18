def view(feed):
    return {"rows": list(feed.client.rows), "last_sequence": feed.resume.last_sequence,
            "sent": sorted(feed.resume.sent)}
