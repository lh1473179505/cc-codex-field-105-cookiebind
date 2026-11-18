class Transport:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.routes = []

    def connect(self, candidate):
        if candidate.address in self.fail:
            raise OSError(candidate.address)
        self.routes.append((candidate.generation, candidate.address))
