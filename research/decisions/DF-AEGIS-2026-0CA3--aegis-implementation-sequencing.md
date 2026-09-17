---
id: DF-AEGIS-2026-0CA3
title: Aegis implementation sequencing
status: accepted
version: 1.1.0
created: 2026-09-17
updated: 2026-09-17
owners:
  - repository-governance
tags: [aegis, sequencing, requirements, synthesis]
related_documents:
  - Input-documents/aegis_initial_requirements.txt
  - Input-documents/aegis_additional_requirements_and_design_ideas.txt
  - Input-documents/aegis_persistent_logging_requirements.txt
  - docs/00-governance/Engineering-Standards.md
supersedes: []
superseded_by: []
---

# Decision Record: Aegis implementation sequencing

**Status: accepted.** The build order this record proposes was executed end to end; the
epics below and the wave ordering are the sequence the repository was actually built in, so the
record now describes history rather than a proposal. It changes no requirement, and the intake it
partitions stands independently of it.

## Context

The three requirements documents under `Input-documents/` were captured as 143
ROS backlog work items, one per numbered section, verified complete at
requirement level. That mapping is deliberate 1:1 transcription: it preserves
traceability but says nothing about what can be built when, and the same
concern recurs across documents (redaction appears in core section 12 and
logging section 21; multiple sinks in core section 24 and logging section 14).

A flat backlog of 143 items with no ordering cannot be planned against. This
record groups them into epics and states the dependency order.

## Decision

Group all 143 requirement items into 15 epics forming a verified
partition -- every item belongs to exactly one epic, no item is unassigned and
no item appears twice. Epic membership is recorded on each work item as an
`epic-<key>` tag, so the grouping is queryable from the tool of record rather
than living only in this document.

The dependency graph is acyclic. Epics with no unmet dependency may proceed in
parallel, giving these waves:

1. E00 Governing constraints and scope
2. E01 Fault model and classification vocabulary
3. E02 Redaction and privacy core
4. E03 Capture API and architectural boundaries, E05 Event model and serialization
5. E04 Translation and integration contracts, E06 Sink runtime, E09 Recovery and obligations, E10 Fault lifecycle and projections
6. E07 Storage adapters and retrieval, E08 Configuration, bootstrap and shutdown, E11 Presentation intent, E12 Diagnostics and agent surface, E13 Test strategy
7. E14 Documentation and ROS compliance

## Sequencing rationale

Three orderings are forced by the requirements themselves rather than chosen:

- **Redaction (E02) precedes every sink and export.** Core section 12 states
  sensitive-data protection is foundational rather than optional, and logging
  section 21 states sinks must never be responsible for deciding whether
  credentials are safe to persist. Redaction therefore cannot be retrofitted
  after a persistence path exists.
- **The event model (E05) precedes the sink runtime (E06) and the lifecycle
  projection (E10).** Logging sections 5, 12 and 13 require a versioned,
  storage-independent event shape; both sinks and the active-fault projection
  are defined in terms of it.
- **Storage adapters (E07) come after the sink runtime (E06), not with it.**
  Logging sections 3, 4 and 42 require adapters to sit outside the core behind
  a standard contract, so the contract must exist first.

E00 is not scheduled work. It collects the governing constraints -- the
architectural rule, dependency limits, scope boundaries and the
responsibility split between Aegis, SDE, Limen, ROS and applications -- which
act as acceptance criteria for every other epic.

## Epics

### E00 -- Governing constraints and scope

**Depends on:** nothing  
**Items:** 12

Cross-cutting principles that constrain every other epic rather than being built once. Reviewed as acceptance criteria throughout, not scheduled as standalone delivery.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-053` | additional §53 | Policy separation across concerns |
| `AEG-ADD-054` | additional §54 | Architectural principle: own the failure lifecycle |
| `AEG-CORE-000` | core §0 | Architectural rule: simpler failure handling without invisible failure |
| `AEG-CORE-001` | core §1 | Purpose: standard mechanism for handling and recovering from unexpected faults |
| `AEG-CORE-035` | core §35 | Dependency constraints |
| `AEG-CORE-036` | core §36 | C# consumability |
| `AEG-CORE-038` | core §38 | Observability without telemetry dependency |
| `AEG-LOG-001` | logging §1 | Purpose: storage-independent persistence of faults and lifecycle events |
| `AEG-LOG-028` | logging §28 | Recording path separate from querying |
| `AEG-LOG-042` | logging §42 | Minimal core dependencies |
| `AEG-LOG-047` | logging §47 | Recommended architectural principle for persistence |
| `AEG-LOG-048` | logging §48 | Scope constraint on persistence |

### E01 -- Fault model and classification vocabulary

**Depends on:** E00  
**Items:** 14

The representation and classification vocabulary every later epic consumes. Nothing can be captured, recorded, recovered or presented before Fault, FailureCategory, codes, severity and impact exist.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-004` | additional §4 | Stable fault fingerprints |
| `AEG-ADD-009` | additional §9 | Fault ownership by subsystem |
| `AEG-ADD-018` | additional §18 | Transient vs persistent classification |
| `AEG-ADD-043` | additional §43 | Failure domains |
| `AEG-ADD-044` | additional §44 | Blast-radius metadata |
| `AEG-ADD-045` | additional §45 | Dependency relationships on faults |
| `AEG-CORE-002` | core §2 | Core distinction between domain and operational failures |
| `AEG-CORE-003` | core §3 | Standard fault model |
| `AEG-CORE-004` | core §4 | Stable machine-readable fault codes |
| `AEG-CORE-015` | core §15 | Preserve fault causal chains |
| `AEG-CORE-017` | core §17 | Preserve original exception information through translation |
| `AEG-CORE-018` | core §18 | Standardized severity classifications |
| `AEG-CORE-037` | core §37 | Schema version on serialized faults |
| `AEG-CORE-039` | core §39 | Application availability impact model |

### E02 -- Redaction and privacy core

**Depends on:** E01  
**Items:** 5

Sequenced before anything persists or exports because the requirements state sensitive-data protection is foundational rather than optional, and sinks must never decide whether credentials are safe to persist.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-027` | additional §27 | Privacy classification for context values |
| `AEG-ADD-040` | additional §40 | Diagnostic export safety |
| `AEG-CORE-011` | core §11 | Separate user-facing, technical and diagnostic information |
| `AEG-CORE-012` | core §12 | Explicit redaction rules for sensitive data |
| `AEG-LOG-021` | logging §21 | Redaction before events reach any sink |

### E03 -- Capture API and architectural boundaries

**Depends on:** E01, E02  
**Items:** 9

The public surface and the rules for where it is used. Depends on the fault model for what it produces and on redaction so captured context is safe from the first call.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-001` | additional §1 | Fault scopes establishing shared diagnostic context |
| `AEG-ADD-022` | additional §22 | Unhandled top-level boundary |
| `AEG-CORE-005` | core §5 | Deliberately small capture API |
| `AEG-CORE-006` | core §6 | Use Aegis at architectural boundaries |
| `AEG-CORE-007` | core §7 | No silent swallowing of faults |
| `AEG-CORE-013` | core §13 | Structured fault context |
| `AEG-CORE-014` | core §14 | Correlation IDs across related operations |
| `AEG-CORE-019` | core §19 | Programming defects fail loudly |
| `AEG-CORE-029` | core §29 | Cancellation is not necessarily a fault |

### E04 -- Translation and integration contracts

**Depends on:** E01, E03  
**Items:** 5

Keeps technology exceptions from crossing integration boundaries and gives each integration assembly a typed failure model, with contract tests proving the translation.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-023` | additional §23 | Integration contract tests for failure translation |
| `AEG-ADD-024` | additional §24 | Schema migration awareness |
| `AEG-CORE-016` | core §16 | Translate low-level exceptions at integration boundaries |
| `AEG-CORE-020` | core §20 | Special treatment for data integrity faults |
| `AEG-CORE-032` | core §32 | Integration assembly responsibility and typed failure models |

### E05 -- Event model and serialization

**Depends on:** E01, E02  
**Items:** 7

The persisted lifecycle event vocabulary and its wire shape, versioned from the start. Storage adapters and the lifecycle projection both build on this.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-LOG-005` | logging §5 | Persist more than faults: the lifecycle event model |
| `AEG-LOG-006` | logging §6 | Append-oriented immutable storage |
| `AEG-LOG-011` | logging §11 | Storage schema consistency across sinks |
| `AEG-LOG-012` | logging §12 | Versioned event schema |
| `AEG-LOG-013` | logging §13 | Standard serialized event shape |
| `AEG-LOG-024` | logging §24 | Distinct event identity |
| `AEG-LOG-025` | logging §25 | UTC timestamp requirements |

### E06 -- Sink runtime

**Depends on:** E05, E03  
**Items:** 27

Sink abstraction, fan-out, independence, failure containment and delivery behaviour, including the guarantee that Aegis survives its own sink failures.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-048` | additional §48 | Sink capability metadata |
| `AEG-ADD-049` | additional §49 | Graceful degradation of optional diagnostics |
| `AEG-ADD-050` | additional §50 | Required vs optional sink requirement levels |
| `AEG-ADD-051` | additional §51 | Aegis health projection |
| `AEG-CORE-022` | core §22 | Bounded in-memory fault history |
| `AEG-CORE-023` | core §23 | Configurable fault sinks |
| `AEG-CORE-024` | core §24 | Multiple simultaneous sinks |
| `AEG-CORE-025` | core §25 | Aegis must survive its own failures |
| `AEG-CORE-030` | core §30 | Agent-readable structured diagnostics |
| `AEG-CORE-031` | core §31 | Human-readable diagnostics derived from the same fault |
| `AEG-LOG-002` | logging §2 | Standard sink abstraction |
| `AEG-LOG-014` | logging §14 | Simultaneous logging to multiple sinks |
| `AEG-LOG-015` | logging §15 | Sink independence on failure |
| `AEG-LOG-016` | logging §16 | Bounded sink failure handling with re-entry guard |
| `AEG-LOG-017` | logging §17 | Primary operation safety on persistence failure |
| `AEG-LOG-018` | logging §18 | Asynchronous persistence |
| `AEG-LOG-019` | logging §19 | Event batching |
| `AEG-LOG-020` | logging §20 | Offline and deferred delivery |
| `AEG-LOG-022` | logging §22 | Consistent correlation across sinks |
| `AEG-LOG-023` | logging §23 | Fault ID preserved on every lifecycle event |
| `AEG-LOG-029` | logging §29 | Agent readability of persisted events |
| `AEG-LOG-030` | logging §30 | Human readability without proprietary tooling |
| `AEG-LOG-032` | logging §32 | Idempotent writes |
| `AEG-LOG-033` | logging §33 | Event ordering reconstruction |
| `AEG-LOG-034` | logging §34 | Concurrent write tolerance |
| `AEG-LOG-038` | logging §38 | Sink health and diagnostics |
| `AEG-LOG-041` | logging §41 | In-memory test sink |

### E07 -- Storage adapters and retrieval

**Depends on:** E06  
**Items:** 15

Concrete durable stores behind the standard contract, kept outside the core, plus the query and retention model that makes history usable.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-041` | additional §41 | Fault searchability on structured fields |
| `AEG-ADD-052` | additional §52 | Retention and aggregation interaction |
| `AEG-LOG-003` | logging §3 | Standard store abstraction |
| `AEG-LOG-004` | logging §4 | Storage adapters outside the core |
| `AEG-LOG-007` | logging §7 | GitHub storage model: one immutable file per event |
| `AEG-LOG-008` | logging §8 | GitHub file naming with sortable unique identifiers |
| `AEG-LOG-009` | logging §9 | GitHub repository configuration |
| `AEG-LOG-010` | logging §10 | Database storage with efficient lookup |
| `AEG-LOG-026` | logging §26 | Retention policy metadata |
| `AEG-LOG-027` | logging §27 | Provider-independent query model |
| `AEG-LOG-031` | logging §31 | Reconstructable audit history |
| `AEG-LOG-035` | logging §35 | GitHub commit strategy |
| `AEG-LOG-036` | logging §36 | GitHub conflict handling |
| `AEG-LOG-037` | logging §37 | Database transaction behaviour for batches |
| `AEG-LOG-043` | logging §43 | Integration assemblies may provide sinks |

### E08 -- Configuration, bootstrap and shutdown

**Depends on:** E06  
**Items:** 5

Declare-once configuration with startup validation, plus fault boundaries that work before state exists and during controlled shutdown.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-020` | additional §20 | Startup fault boundary and bootstrap mode |
| `AEG-ADD-021` | additional §21 | Shutdown fault boundary |
| `AEG-ADD-047` | additional §47 | Configuration validation at startup |
| `AEG-CORE-026` | core §26 | Configure Aegis once at initialization |
| `AEG-LOG-039` | logging §39 | Declare sinks once in configuration |

### E09 -- Recovery and obligations

**Depends on:** E01, E03, E05  
**Items:** 10

Recovery policy, retry safety, verification that recovery actually worked, and the obligations and safe-mode requests that Aegis proposes but SDE authorizes.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-015` | additional §15 | Recovery verification |
| `AEG-ADD-016` | additional §16 | Fault obligations |
| `AEG-ADD-019` | additional §19 | Safe-mode support |
| `AEG-ADD-028` | additional §28 | Machine-remediation hooks |
| `AEG-ADD-037` | additional §37 | Recordable recovery attempts |
| `AEG-ADD-038` | additional §38 | Recovery actors |
| `AEG-ADD-039` | additional §39 | Manual intervention representation |
| `AEG-CORE-008` | core §8 | Recovery policy model |
| `AEG-CORE-009` | core §9 | SDE integration: faults may propose transitions |
| `AEG-CORE-021` | core §21 | Retry only under explicit policy |

### E10 -- Fault lifecycle and projections

**Depends on:** E05  
**Items:** 12

The lifecycle Aegis owns beyond exception capture: immutable events, the active-fault projection derived from them, resolution, reopening, supersession, deduplication and escalation.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-003` | additional §3 | Fault deduplication |
| `AEG-ADD-005` | additional §5 | Policy-driven escalation rules |
| `AEG-ADD-017` | additional §17 | Acknowledged is not resolved |
| `AEG-ADD-029` | additional §29 | Fault lifecycle model |
| `AEG-ADD-030` | additional §30 | Fault immutability and event-based lifecycle changes |
| `AEG-ADD-031` | additional §31 | Active fault projection derived from event history |
| `AEG-ADD-032` | additional §32 | Explicit fault resolution |
| `AEG-ADD-033` | additional §33 | Fault reopening |
| `AEG-ADD-034` | additional §34 | Fault supersession |
| `AEG-ADD-035` | additional §35 | Repeated transient fault behaviour |
| `AEG-ADD-036` | additional §36 | Escalation as a lifecycle event |
| `AEG-ADD-046` | additional §46 | Root-cause grouping |

### E11 -- Presentation intent

**Depends on:** E01, E10  
**Items:** 4

Structured presentation intent and noise control for Limen to render, without Aegis generating UI.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-025` | additional §25 | User notification policy via presentation intent |
| `AEG-ADD-026` | additional §26 | UI noise rate limiting |
| `AEG-CORE-010` | core §10 | Limen integration: standardized fault presentation model |
| `AEG-LOG-045` | logging §45 | Limen integration for persistence state |

### E12 -- Diagnostics and agent surface

**Depends on:** E01, E06  
**Items:** 10

The operator- and agent-facing diagnostic layer: breadcrumbs, environment and deployment metadata, bundles, the known-fault catalog, and the containment behaviours that consume fault state.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-ADD-002` | additional §2 | Bounded breadcrumb trail |
| `AEG-ADD-006` | additional §6 | Expose fault state for circuit-breaker adapters |
| `AEG-ADD-007` | additional §7 | Quarantine support for unprocessable data |
| `AEG-ADD-008` | additional §8 | Dead-letter handling |
| `AEG-ADD-010` | additional §10 | Environment metadata on diagnostic events |
| `AEG-ADD-011` | additional §11 | Deployment and revision correlation |
| `AEG-ADD-012` | additional §12 | State snapshot references for serious faults |
| `AEG-ADD-013` | additional §13 | Diagnostic bundles |
| `AEG-ADD-014` | additional §14 | Known-fault catalog |
| `AEG-ADD-042` | additional §42 | Agent diagnostic guidance on known faults |

### E13 -- Test strategy

**Depends on:** E03, E06  
**Items:** 3

Deterministic testability as a design constraint plus the concrete suites the requirements enumerate for the package and for every sink.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-CORE-027` | core §27 | Deterministic testability with replaceable sinks |
| `AEG-CORE-028` | core §28 | Unit-test coverage for the Aegis package |
| `AEG-LOG-040` | logging §40 | Deterministic tests per sink implementation |

### E14 -- Documentation and ROS compliance

**Depends on:** E03, E07  
**Items:** 5

The teaching documentation the requirements mandate, the declared fault boundaries and persistence declarations ROS should enforce, and closing out the initial pass's open design questions.

| Work item | Source | Requirement |
|---|---|---|
| `AEG-CORE-033` | core §33 | ROS integration: declared fault boundaries |
| `AEG-CORE-034` | core §34 | Documentation requirement |
| `AEG-CORE-040` | core §40 | Close out initial-pass open design questions |
| `AEG-LOG-044` | logging §44 | SDE integration for persistence state |
| `AEG-LOG-046` | logging §46 | ROS integration for persistence declarations |

## Consequences

- The backlog becomes plannable: 7 waves instead of one flat list of
  143 items, with parallelism made explicit.
- Epic membership is mechanically checkable. The partition property (every item
  in exactly one epic) can be re-verified whenever items are added.
- Items whose scope spans an epic boundary were assigned to the epic that must
  deliver them first; cross-cutting topic tags still link them elsewhere.
- Some epics remain coarse. `AEG-CORE-028` enumerates 14 test areas and
  `AEG-LOG-040` enumerates 14 sink test cases; both sit in E13 as single items
  and would need splitting before execution.

## Alternatives considered

- **Keep the flat 1:1 backlog.** Rejected: maximally traceable but not
  plannable, and it leaves cross-document duplicates to be rediscovered
  during implementation.
- **Group by source document.** Rejected: the documents are three passes over
  one system, not three subsystems, so document boundaries cut across
  concerns.
- **Group by topic tag alone.** Rejected: topic tags already provide thematic
  retrieval and are kept, but they overlap by design and so cannot express a
  build order.

## Resolved at acceptance

The two questions this record left open were settled by executing it, and are
recorded here rather than left open behind an accepted status.

- **Wave ordering versus a thinner vertical slice.** A vertical slice went
  first. Execution did not follow the waves breadth-first: `AEG-SLICE-001`
  delivered the fault model, redaction, capture and one in-memory sink across
  E01, E02, E03 and E06 before any of those epics was complete, and the
  remaining slices widened from there. The wave *dependencies* held -- no slice
  needed an epic its predecessors had not reached -- but the delivery unit was
  the slice, not the wave. The dependency graph is what this record
  contributes; the wave numbering is a consequence of it, not a schedule.
- **When to split coarse items.** When their epic starts. `AEG-CORE-028` and
  `AEG-LOG-040` were never split as backlog items; their enumerated test areas
  became the acceptance criteria of `AEG-SLICE-009`, which closed the gaps the
  enumeration exposed. Splitting them up front would have produced 28 items
  that no one planned against.

## Follow-up validation

The partition property was re-verified against the backlog after execution:
143 requirement items, each carrying exactly one `epic-eNN` tag, no item
unassigned and none tagged twice. Per-item delivery status is tracked in
[`docs/aegis/REQUIREMENTS-STATUS.md`](../../docs/aegis/REQUIREMENTS-STATUS.md),
not here, so this record does not need to change as items close.
