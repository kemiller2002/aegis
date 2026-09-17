---
id: GV-AEGIS-002
title: Initial-pass open questions, closed out
status: draft
version: 1.0.0
owners:
  - repository-governance
created: 2026-09-17
related_documents:
  - Input-documents/aegis_initial_requirements.txt
  - Input-documents/aegis_additional_requirements_and_design_ideas.txt
  - Input-documents/aegis_persistent_logging_requirements.txt
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

## What is genuinely still open

These are not from section 40; they are decisions this implementation reached
and deliberately left to a human.

1. **`FaultSeverity.Error` shadows `Result.Error`.** Eight call sites now
   qualify it as `FaultSeverity.Error`. Renaming the case would remove the
   collision but changes vocabulary that core 18 names explicitly, so it is a
   deliberate API decision rather than a cleanup.
2. **Limen interop is declared but unguarded.** `aegis-boundaries.json`
   records it as `guarded: false` because Limen does not exist in this
   repository. The declaration keeps the gap visible.
3. **Only the GitHub store adapter exists.** Logging 4 lists Postgres, SQL
   Server and SQLite adapters as well; the store contract is in place and
   unexercised by those.
4. **The sequencing decision record is still `review`.** `DF-AEGIS-2026-0CA3`
   proposed the build order that was then followed under standing
   authorization. Moving it to `accepted` makes it immutable, which is a
   judgement for the repository owner.
5. **Circuit-breaker state is exposed, not enforced.** Additional 6 says Aegis
   need not become a resilience framework; `Containment.circuit` supplies the
   state for an adapter to act on, and no adapter does yet.
