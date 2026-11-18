# Queue recovery contract
Receipt numbers are exposed to existing clients and must remain monotonic after a
visibility timeout. `queue-v1` captures item state for offline recovery. A remote
deletion is atomic per body, not per supplied batch; acknowledgement must describe
the remote outcome. Read-only inspection never changes visibility deadlines.
