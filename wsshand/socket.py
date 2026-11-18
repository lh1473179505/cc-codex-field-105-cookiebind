class Socket:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.messages = []

    def send(self, session, text):
        if text in self.fail:
            raise OSError(text)
        self.messages.append((session, text))
