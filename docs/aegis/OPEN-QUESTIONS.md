---
id: GV-AEGIS-002
title: Initial-pass open questions, closed out
status: draft
version: 1.1.0
owners:
  - repository-governance
created: 2026-09-17
updated: 2026-09-17
related_documents:
  - Input-documents/aegis_initial_requirements.txt
  - Input-documents/aegis_additional_requirements_and_design_ideas.txt
  - Input-documents/aegis_persistent_logging_requirements.txt
  - research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md
  - research/decisions/DF-AEGIS-2026-0CA3--aegis-implementation-sequencing.md
tags: [aegis, traceability]
---

# Initial-pass open questions, closed out

Section 40 of `aegis_initial_requirements.txt` listed fifteen unresolved
questions and said the next requirements pass should answer them. This records
where each was answered and where it is implemented, which is the work item
`AEG-CORE-040` asked for.

| Question | Answered by | Implemented in |
| --- | --- | --- |
| Should a fault itself always be immutable? | additional 30 | Lifecycle changes are new events; `Lifecycle.apply` never mutates a stored `Fault` |
| How is a fault acknowledged? | additional 17 | `FaultAcknowledged`, projecting to `AcknowledgedActive` |
| Can faults become obligations? | additional 16, 39 | `Recovery.Obligation`, raised from the fault's policy and category |
| How are retry and recovery transitions represented in SDE? | core 9; additional 19 | `Sde.forFault`, `Sde.forSafeMode` — proposals only |
| What is an active fault versus historical information? | additional 31 | `Lifecycle.active` over the projection |
| When is a fault resolved? | additional 32 | `FaultResolved` with resolution metadata, including whether it was verified |
| Should resolution be a state transition? | additional 30, 32 | An event, not a mutation; the projection derives state |
| Can one fault supersede another? | additional 34 | `FaultSuperseded`, preserving the original |
| How are duplicates collapsed or grouped? | additional 3, 4 | Fingerprints and `Lifecycle.byFingerprint` |
| How are repeated transient faults represented? | additional 35 | Occurrence and reopening counts, first/last seen |
| How should escalation work? | additional 5, 36 | `Escalation.evaluate`, which can only raise severity |
| How should Aegis behave during startup? | additional 20 | `Bootstrap.minimal` and `Bootstrap.promote` |
| How should Aegis behave during shutdown? | additional 21 | `Bootstrap.shutdown`, single pass, no retry loop |
| How should faults be exported? | additional 13, 40 | `Diagnostics.export`, redacting after aggregation |
| How should offline applications queue events? | logging 20 | `Offline.Queue`, preserving identity and order |
| How should schemas evolve without breaking consumers? | logging 12 | Versioned events, with compatibility tests |

All fifteen are answered by the later passes, so nothing from section 40
remains open as a requirement.

## Implementation status

Measured against the 143 requirement items, not asserted:

| | Count |
| --- | --- |
| Fully implemented and tested | 137 |
| Partial | 4 |
| Not implemented | 2 |

Everything still short of complete traces to one of two causes: work that is
deliberately outside this repository's scope, or a dependency that does not
exist in this repository yet. Neither is unfinished effort.

- `AEG-LOG-010`, `AEG-LOG-037`, `AEG-LOG-004` and the enforcement half of
  `AEG-ADD-052` are out of scope here per
  [`DF-AEGIS-2026-DBBD`](../../research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md):
  database adapters are built against `Store.T` where the driver dependency
  belongs. They are blocked against that record, not abandoned -- the
  requirements stay true of Aegis as a system, and an adapter repository
  satisfies them.
- `AEG-LOG-044` has the SDE proposals; there is no SDE here to consume them.
- `AEG-CORE-033` has the declaration and the tests that keep it honest, but
  ROS itself does not yet require or validate a fault-boundary declaration.
  That is upstream of this repository.

## What is genuinely still open

These are not from section 40; they are decisions this implementation reached
and deliberately left to a human.

1. **`FaultSeverity.Error` shadows `Result.Error`.** Eight call sites now
   qualify it as `FaultSeverity.Error`. Renaming the case would remove the
   collision but changes vocabulary that core 18 names explicitly, so it is a
   deliberate API decision rather than a cleanup.
2. **Circuit-breaker state is exposed, not enforced.** Additional 6 says Aegis
   need not become a resilience framework; `Containment.circuit` supplies the
   state for an adapter to act on, and no adapter does yet.

## Closed since the first pass

Three entries that were open here have been decided. They are kept, rather
than deleted, so a reader can see what was decided and not just what is left.

- **Store adapters beyond GitHub**, and their six sub-questions (ownership,
  engines, dependency shape, schema ownership and migration, transaction
  behaviour, retention enforcement). Answered by
  [`DF-AEGIS-2026-DBBD`](../../research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md),
  which puts database adapters outside this repository, against `Store.T`,
  where the driver dependency belongs. Each of the six is answered
  individually in that record. `AEG-STORE-ADAPTERS-001` is closed by it.
- **The Limen install.** The tooling
  (`@echelon-foundry/typescript-wasm-kernel`) was removed: this repository has
  no TypeScript and no WASM, and the install's verification could only pass
  with both boundary lists emptied. Limen is retained as a *reference
  consumer* -- `aegis-boundaries.json` still declares the `Limen interop`
  boundary as `guarded: false`, the presentation model is shaped for a UI
  layer of that kind, and [`README.md`](README.md) still explains how faults
  reach it. Core 10 and logging 45 are satisfied without the package.
- **The sequencing decision record's status.** `DF-AEGIS-2026-0CA3` is now
  `accepted` at version 1.1.0, with its own two open questions answered from
  what execution showed rather than frozen unanswered behind an immutable
  status.
