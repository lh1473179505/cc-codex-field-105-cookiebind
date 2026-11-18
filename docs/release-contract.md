# Durable log compatibility

A checkpoint is a dense committed prefix. Prepared entries may have blob
storage, but aborted work cannot consume positions visible through the
version-1 audit export. `head` remains the number of exported entries;
it is not a high-water allocation counter.

Appending and process recovery must produce the same checkpoint for the
same committed set. A failed batch is atomic even when its first entry
is valid. Existing `version: 1` consumers and their entry field names
remain supported. Recovery never verifies an aborted signature again.
