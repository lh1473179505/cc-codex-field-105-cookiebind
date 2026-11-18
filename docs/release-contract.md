# Multi-output durability

Publication replaces a complete output set atomically. Existing output
bytes remain readable until commit, and rollback restores overwritten
files rather than merely removing their names. Restart cleanup follows
the same ownership rule as online rollback.

Bundle publication and direct rendering use identical import closure
snapshots. Legacy output paths are relative slash paths and remain
readable as UTF-8 text; no manifest reordering changes their contents.
Output signatures cover one path and digest but do not transfer file
ownership between transactions.
