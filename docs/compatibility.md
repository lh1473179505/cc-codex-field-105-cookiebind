# Fan-out consumers
Reports retain subscriber-name keys and per-subscriber body order. A notice is
complete only after every subscriber current at publish time accepts it. Retrying
one subscriber must not resend it to subscribers that already succeeded. The
fanout-v1 archive is restored together with the same registry, not a new audience.
