from .batch_writer import Writer
from .flow_control import Windows
from .priority import PriorityTree
from .stream_state import StreamTable

class Connection:
    def __init__(self, fail=()):
        self.table = StreamTable()
        self.priority = PriorityTree()
        self.windows = Windows()
        self.writer = Writer(fail)

    def open(self, stream, epoch, parent=0):
        self.table.open(stream, epoch)
        self.priority.depend(stream, parent)

    def reset(self, stream):
        self.table.reset(stream)

    def submit(self, frames):
        self.writer.flush(frames, self.table, self.windows)

    def snapshot(self):
        return {"format": "h2-state-1", "epochs": dict(self.table.epochs),
                "parents": self.priority.capture(), "sent": dict(self.windows.sent)}
