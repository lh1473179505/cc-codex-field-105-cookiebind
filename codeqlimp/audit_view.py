"""Independent read-only audit consumer of the same public state."""
from __future__ import annotations

from .entities import State
from .legacy_report import LegacyReporter


def render_audit(state: State, reporter: LegacyReporter) -> dict[str, object]:
    return {
        "schema": "audit-v1",
        "operations": list(state.history),
        "report": reporter.render(state),
    }
