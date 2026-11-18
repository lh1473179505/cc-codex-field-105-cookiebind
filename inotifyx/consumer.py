def pump(watches, queue):
    delivered = []
    for event in queue.read_all():
        watches.apply(event)
        delivered.append(event)
    return delivered
