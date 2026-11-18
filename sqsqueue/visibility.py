class Visibility:
    def __init__(self):
        self.clock = 0
        self.deadlines = {}

    def tick(self, amount=1):
        self.clock += amount

    def hide(self, item):
        item.state = "inflight"
        item.receipt += 1
        self.deadlines[item.key] = self.clock + 5

    def expire(self, items):
        for item in items:
            if item.state == "inflight" and self.deadlines[item.key] <= self.clock:
                item.state = "available"
