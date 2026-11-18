# Overlay cache and epoch continuity

The render cache memoizes deterministic documents, never permission to
publish. Every live release and snapshot rebuild verifies its signature
in the requested epoch, including when bytes match an earlier release.
Revocation affects new publications but does not rewrite historical
audit records.

Cache hits cannot advance the release sequence. A failed output write
leaves both sequence and cache authorization unchanged. Legacy audit
retains the `sequence`, `digest`, and ordered resource-name fields;
resource order is part of the rendered content and is not sorted again.
