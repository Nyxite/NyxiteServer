# Nyxite Server — Features

ASP.NET Core (C#) backend. The core service: API, sync engine, real-time collaboration, encryption, authentication, and administration.

## API

- REST and WebSocket API surface for all clients

## Domain

- Projects and folders
- Files: markdown, handwritten ink, plain text

## Sync

- Cross-device sync engine
- Per-file sync policies enforced server-side: server-default, pinned-local, excluded

## Collaboration

- Server-authoritative real-time collaboration (CRDT via Ycs)
- Anonymous guests join collaborative sessions with no key exchange

## Sharing

- Server-side access-control lists
- Share links with clean revocation

## Version history

- Full version history
- Server-side history diffs

## Search

- Server-side full-text search

## Encryption

- Encryption at rest via envelope encryption
- Per-file AES-256-GCM data keys wrapped by a master key (KEK) held outside the database

## Authentication

- Keycloak integration
- TOTP two-factor

## Administration

- Instance and user management
- Default policy: admins do not browse file contents; break-glass access is audit-logged

## Open questions

- KEK storage: environment secret now, Vault later? (default: env secret first)
- Admin content access: no casual access, audit-logged break-glass only? (default: yes)
- Sync policy semantics: pinned-local = always-offline + synced; excluded = device-only, never uploaded? (default: as written)
- Per-file-type sync split: CRDT for text, last-write-wins for ink and binary? (default: yes)
- Zero-knowledge mode: leave hooks in the file and key schema from Phase 0, or retrofit later? (default: defer the feature; leaving schema room now is cheaper than a later migration)
