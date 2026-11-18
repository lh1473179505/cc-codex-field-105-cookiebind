class Counters:
    def __init__(self):
        self.units = {0: 0, 1: 0}

    def acquire(self, cpu):
        self.units[cpu] += 1

    def release(self, cpu):
        self.units[cpu] -= 1
