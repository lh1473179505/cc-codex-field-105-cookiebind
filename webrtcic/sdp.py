class Description:
    def __init__(self):
        self.generation = 1
        self.stable = False

    def restart(self):
        self.generation += 1
        self.stable = False

    def mark_stable(self):
        self.stable = True
