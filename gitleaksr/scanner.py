"""Application API; snapshot and delta paths remain separate writers."""
from __future__ import annotations

from .secret_records import State
from .redaction_log import OperationJournal
from .digest_cache import FingerprintIndex
from .tree_snapshot import merge_snapshot
from .commit_delta import apply_delta
from .finding_view import Projector
from .legacy_redaction import LegacyReporter
from .audit_export import render_audit


class ScanService:
    def __init__(self) -> None:
        self.state = State()
        self.index = FingerprintIndex()
        self.journal = OperationJournal()
        self.projector = Projector()
        self.reporter = LegacyReporter(self.projector)

    def snapshot(self, *, generation: int, sequence: int, rows: list[dict[str, object]]) -> dict[str, object]:
        return merge_snapshot(self.state, self.index, self.journal,
                              generation=generation, sequence=sequence, rows=rows)

    def delta(self, *, action: str = "delta", key: str, fingerprint: str, value: str,
              sequence: int, scope: str = "main") -> dict[str, object]:
        return apply_delta(self.state, self.index, self.journal, action=action, key=key,
                           fingerprint=fingerprint, value=value, sequence=sequence, scope=scope)

    def report(self) -> dict[str, object]:
        return self.reporter.render(self.state)

    def audit(self) -> dict[str, object]:
        return render_audit(self.state, self.reporter)

    def state_token(self) -> str:
        return self.state.token()
