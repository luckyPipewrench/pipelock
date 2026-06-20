# Monotonic State Threat Boundary

Pipelock uses small local state records for rollback and replay floors:
license CRL high-water generation, rules-bundle freshness, conductor
remote-kill counters, and conductor enrollment markers.

The required invariant is fail-closed: if surrounding context says a floor
should exist, missing or corrupt floor state is treated as suspect and requires
an explicit operator reset. A deleted floor must not silently become first-run
while the protected artifact remains available for replay.

The implemented boundary is selective-deletion resistance. An attacker cannot
delete only the floor records while keeping the replay target, such as an older
CRL, installed v2 rules bundle, or conductor follower context, and cause
Pipelock to accept the older value.

The residual boundary is full local state ownership. An attacker with full write
control over both the proxy state and the protected artifact can wipe or replace
the entire local context. That actor already controls the local proxy state; the
operator recovery path is to verify the current artifact out of band and run the
explicit reset command for that surface.
