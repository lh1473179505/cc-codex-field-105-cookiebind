# Cache lifetime rules

A published manifest owns every layer in its ordered layer list. A new
export must pin reused content before it can fail; rollback releases
only references acquired by that transaction. Recovery garbage
collection therefore cannot remove content reachable from an older
manifest.

Cache restoration and ordinary exports share these ownership rules.
The version-one reader returns layer contents in manifest order and its
diagnostic object keeps the `cache` and `layers` keys. Signature epochs
authorize an export but never transfer ownership of existing content.
