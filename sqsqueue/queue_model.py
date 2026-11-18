from dataclasses import dataclass

@dataclass
class Item:
    key: str
    body: str
    state: str = "available"
    receipt: int = 0
