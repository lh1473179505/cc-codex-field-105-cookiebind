# SARIF gate compatibility
Findings staged before a rule quarantine must be re-evaluated against the quarantine
set before the first index write. `sarif_results` keeps stable ordering by
`(ruleId, finger)` for a downstream diff tool. `sarif-gate-1` snapshots omit
pending batches; `published` means indexed, not merely staged.
