# Stream reuse and flow accounting
RST_STREAM ends one epoch of a stream identifier; a later epoch may reuse that id.
Buffered frames retain their originating epoch. Existing response consumers require
`(epoch, stream, payload)` rows, and h2-state-1 snapshots preserve priority parents
separately from byte windows. A failed batch can contain already successful frames;
retrying it must neither duplicate those rows nor reserve their bytes again.
