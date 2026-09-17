---
id: DF-AEGIS-2026-DBBD
title: Aegis repository scope
status: accepted
version: 1.1.0
created: 2026-09-17
updated: 2026-09-17
owners:
  - repository-governance
tags: [aegis, scope, adapters, tooling]
related_documents:
  - Input-documents/aegis_persistent_logging_requirements.txt
  - Input-documents/aegis_initial_requirements.txt
  - research/decisions/DF-AEGIS-2026-0CA3--aegis-implementation-sequencing.md
  - docs/aegis/OPEN-QUESTIONS.md
  - aegis-boundaries.json
supersedes: []
superseded_by: []
---

# Decision Record: Aegis repository scope

**Status: accepted.** Directed by the repository owner. This record draws the
boundary of what this repository ships; it removes no requirement from the
intake.

## Context

Two things had been left undecided, and both were the same kind of question:
what belongs in this repository.

**Database store adapters.** Logging section 4 requires storage adapters to
live outside the core and names Postgres, SQL Server and SQLite alongside
GitHub. Only the GitHub adapter was built. `AEG-STORE-ADAPTERS-001` recorded
six open questions -- ownership, engine coverage, dependency shape, schema
ownership and migration, transaction behaviour, retention enforcement -- and
sat `blocked` because none of them is answerable by effort. The shape of the
answer depends on where the adapter lives, so ownership had to be settled
first.

**Limen tooling.** `limen init` (`@echelon-foundry/typescript-wasm-kernel`
0.5.1) was run here and installed `limen.config.json`, a tool-owned
`limen-verify` workflow and `.echelon/limen.json`. Limen separates a
TypeScript engine from a WASM kernel. This repository contains no TypeScript
and no WASM: it is F# on .NET 8. The install's own verification could only be
made to pass by emptying both boundary lists, which is the shape of a tool
that has nothing to check -- a green check that proves nothing is worse than
no check, because it earns trust it cannot repay.

Both are distinct from the *requirements* that mention them. Core 10 and
logging 45 require Aegis to expose a presentation model a UI layer such as
Limen can consume; that is implemented in `Presentation.fs` and tested, and it
depends on no Limen package. Logging 3 and 4 require a storage contract
adapters can be written against; `Store.T` and the query model exist and the
GitHub adapter exercises them. The requirements are met without either
artifact being present.

## Decision

This repository ships three assemblies and nothing more:

| Assembly | Responsibility |
|---|---|
| `Aegis.Core` | The fault model, capture, redaction, lifecycle, recovery, escalation, presentation, diagnostics, containment, sinks and the `Store.T` contract |
| `Aegis.Store.GitHub` | The GitHub storage adapter: one immutable file per event |
| `Aegis.Integration.GitHub` | The typed GitHub failure model and its translation mapping |

Consequently:

1. **Database store adapters are out of scope here.** Postgres, SQL Server and
   SQLite adapters are not built in this repository. They are built against
   `Store.T` where the driver dependency belongs -- alongside whatever already
   owns that engine's connection -- which is the same argument logging 43
   makes for giving GitHub API code to the integration layer. The contract is
   the deliverable; the adapters are consumers of it. The GitHub adapter stays
   because it is the reference implementation that keeps the contract honest,
   and because its dependency is an injected `Operations` record rather than a
   client library.

2. **Limen tooling is removed from this repository.** `limen.config.json`,
   `.github/workflows/limen-verify.yml` and `.echelon/limen.json` are deleted.
   Limen is retained as a *reference consumer*: the presentation model in
   `Presentation.fs` is shaped for a UI layer of that kind, `aegis-boundaries.json`
   keeps the `Limen interop` boundary declared and `guarded: false`, and
   `docs/aegis/README.md` keeps explaining how faults reach it. Nothing about
   that needs the package installed.

3. **The six store-adapter questions are answered by (1), not left open.**
   Their answers are recorded below so `AEG-STORE-ADAPTERS-001` can close
   rather than linger.

## The six questions, answered

- **Ownership.** Outside this repository, with the code that owns the engine's
  connection. Logging 4 already puts adapters outside the core; this puts them
  outside the core *repository*, which is the same principle applied one level
  out.
- **Engines.** Not decided here, because it is no longer this repository's
  decision. Each adapter repository covers the engine its consumer needs. No
  engine matrix is maintained speculatively.
- **Dependency shape.** Logging 42's constraint is satisfied structurally: a
  driver dependency cannot reach the core if it is not in the solution. Each
  adapter carries its own driver, or takes injected command execution the way
  `Aegis.Store.GitHub` takes injected operations.
- **Schema ownership and migration.** The adapter owns its schema and its
  migrations. Aegis's own migration faults (additional 24) are raised *about*
  such a migration, not *by* Aegis performing one -- so the two do not
  interact beyond the adapter reporting through `Store.T`.
- **Transaction behaviour.** Per adapter, and documented by that adapter, as
  logging 37 requires. Batch semantics are observable, so each adapter states
  whether a failed batch rolls back wholly, persists valid events
  independently, or quarantines the failures. `Store.T` already carries
  `Retention` and per-event identity, which is what makes all three
  expressible.
- **Retention enforcement.** The adapter enforces it, per logging 26. Retention
  *intent* travels on every event from the core; `AEG-ADD-052`'s guarantee that
  aggregation cannot destroy an audit-required occurrence is therefore stated
  and carried here, and honoured there.

## Consequences

- `AEG-LOG-010` and `AEG-LOG-037` (database storage, database batch
  transactions) are not deliverable in this repository. They are blocked
  against this record rather than abandoned, because the requirements remain
  true of Aegis as a system -- an adapter repository satisfies them.
- `AEG-LOG-004` and `AEG-ADD-052` stay partial with their reasons re-pointed at
  this record instead of at an undecided question.
- The `limen-verify` check disappears from CI. Three workflows become two
  (`ros-validation`, `build`), and no check claims to verify a boundary that
  does not exist here.
- `TSWK-INSTALL-001` remains a complete work item. It records that the install
  happened and how; this record removes its artifacts. History is not rewritten
  to pretend the install never occurred.
- Reversible cheaply: `npx @echelon-foundry/typescript-wasm-kernel init`
  reinstates the tooling, and a database adapter can be added to this solution
  later by superseding this record. Nothing in the core changes either way,
  which is the point -- scope is a packaging decision, not an architectural one.

## Follow-up validation

The decision is checked rather than trusted, because a scope boundary that
only exists in prose drifts.

- `aegis-boundaries.json` records `databaseAdapters.status` as `out-of-scope`
  naming this record, and `BoundaryTests.fs` requires any adapter status to
  name its traceability -- the work item while the question is open, the
  decision record once it is closed. That test failed the moment the status
  changed, which is what a declaration check is for; it was generalised rather
  than retargeted at the new literal, so neither posture can be committed
  without a reference nobody can follow.
- `Aegis.Core.fsproj` has no `PackageReference`. That is the machine-checkable
  form of decision (1): the core cannot acquire a driver dependency from an
  adapter that is not in the solution.
- The removal is complete rather than partial: nothing under this repository
  references `limen.config.json`, `limen-verify` or
  `@echelon-foundry/typescript-wasm-kernel` except this record,
  `docs/aegis/OPEN-QUESTIONS.md` and the ROS work log that records the
  install having happened -- all three of which are meant to. CI runs two
  workflows where it ran three.
- `AEG-LOG-004`, `AEG-LOG-010`, `AEG-LOG-037` and `AEG-ADD-052` are `blocked`
  against this record in the ROS backlog, with the reason on each item, so the
  scope boundary is queryable from the backlog and not only readable here.

## Alternatives considered

- **Build one database adapter here (SQLite) as a second reference.** Rejected
  for now: it would prove the contract generalises beyond a file-per-event
  store, which is real value, but it puts a driver dependency in the solution
  the core must stay free of and commits this repository to a schema and a
  migration story for an engine no consumer has asked for. If the contract
  turns out to be GitHub-shaped, that will surface in the first real adapter
  and is cheaper to fix then than to guess at now.
- **Keep the Limen install and leave the boundary lists empty.** Rejected: a
  passing check over an empty boundary set is a false signal, and a tool-owned
  workflow that can never fail is maintenance with no return.
- **Keep `AEG-STORE-ADAPTERS-001` blocked and decide nothing.** Rejected: the
  item was blocked on ownership, and ownership is now settled. Leaving it
  blocked would misrepresent a made decision as a pending one.
