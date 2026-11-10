# Nyxite.Crdt

Client-side CRDT glue shared with the desktop app (server 01 §1.2).
The server runs no CRDT engine, so `Nyxite.Server` must never reference this project (enforced by `ArchitectureTests`).
The Yrs wire vectors (P0.1-CORE-3) and the `ydotnet` binding land here once the CRDT spike is decided.
