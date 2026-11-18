class Snapshot:
    def save(self, resume):
        state = resume.capture()
        state["format"] = "sse-resume-1"
        return state

    def load(self, state):
        from .resume import Resume
        resume = Resume()
        resume.last_sequence = state["last_sequence"]
        resume.sent = set(state["sent"])
        return resume
