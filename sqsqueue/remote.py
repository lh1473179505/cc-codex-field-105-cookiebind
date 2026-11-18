class Remote:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.deleted = []

    def delete(self, bodies):
        for body in bodies:
            if body in self.fail:
                raise OSError(body)
            self.deleted.append(body)
