"""Independent read-only audit consumer of the same public state."""
from __future__ import annotations

from .secret_records import State
from .legacy_redaction import LegacyReporter


def render_audit(state: State, reporter: LegacyReporter) -> dict[str, object]:
    return {
        "schema": "audit-v1",
        "operations": list(state.history),
        "report": reporter.render(state),
    }
