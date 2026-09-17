---
id: GV-AEGIS-003
title: Requirement traceability and status
status: draft
version: 1.2.0
owners:
  - repository-governance
created: 2026-09-17
updated: 2026-09-17
related_documents:
  - docs/aegis/OPEN-QUESTIONS.md
  - research/decisions/DF-AEGIS-2026-0CA3--aegis-implementation-sequencing.md
  - research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md
  - aegis-boundaries.json
tags: [aegis, traceability, status]
---

# Requirement traceability and status

Every one of the 143 requirement items: where it came from, where it is
implemented, where it is tested, and whether it is done. Generated from the ROS
backlog and the implementation audit rather than written by hand, so it can be
regenerated instead of drifting.

| Done | Partial | Not started |
| --- | --- | --- |
| 137 | 4 | 2 |

Implementation and test columns are at module granularity, which is the honest
resolution: a requirement is delivered by a module and its tests, not by a
single line. Paths are relative to `src/Aegis.Core/` and
`tests/Aegis.Core.Tests/` unless stated otherwise.

Nothing short of `done` is merely unfinished. Each is either outside this
repository's declared scope or waiting on a dependency that does not exist
here; the reason is in the note column, the scope boundary is
[`DF-AEGIS-2026-DBBD`](../../research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md)
and the detail is in [`OPEN-QUESTIONS.md`](OPEN-QUESTIONS.md).

## How this maps onto the backlog

The ROS backlog carried all 143 requirement items and the 15 epics of
[`DF-AEGIS-2026-0CA3`](../../research/decisions/DF-AEGIS-2026-0CA3--aegis-implementation-sequencing.md)
as `captured` long after the work was delivered, which made the backlog and
this table two independent claims about the same repository. They are now one
claim: every item was transitioned epic by epic against the status column
below, so the two cannot drift without one of them being wrong.

| This table | Backlog state | Count |
| --- | --- | --- |
| `done` | `complete`, with the epic's modules and tests as evidence | 137 |
| `partial`, `not started` | `blocked`, with the reason on the item | 6 |
| (epics) | `complete` | 15 |

Two details are deliberate rather than tidy.

`blocked`, not `abandoned`. Four items are outside this repository's scope
(database adapters) and two wait on a dependency that does not exist here
(ROS-side boundary enforcement; an SDE instance). None of them is a
requirement anyone withdrew, so abandoning them would delete a true statement
about Aegis. Each blocked item carries its reason, and the reason names the
record or the dependency rather than restating the requirement.

`E07` and `E14` are complete while holding blocked members. An epic groups
items; it is not a gate over them. Both are complete for what this repository
owns -- the `Store.T` contract and its reference adapter, the teaching
documentation and the boundary declaration -- and the outstanding part stays
visible at item granularity, where the reason can be specific. Recording the
epics as blocked instead would imply pending work here, which is the less
accurate of the two readings.

| Item | Source | Requirement | Status | Implemented in | Tested in | Note |
| --- | --- | --- | --- | --- | --- | --- |
| `AEG-ADD-001` | additional §1 | Fault scopes establishing shared diagnostic context | done | Capture.fs | Tests.fs |  |
| `AEG-ADD-002` | additional §2 | Bounded breadcrumb trail | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-003` | additional §3 | Fault deduplication | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-004` | additional §4 | Stable fault fingerprints | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-ADD-005` | additional §5 | Policy-driven escalation rules | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-006` | additional §6 | Expose fault state for circuit-breaker adapters | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-007` | additional §7 | Quarantine support for unprocessable data | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-008` | additional §8 | Dead-letter handling | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-009` | additional §9 | Fault ownership by subsystem | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-ADD-010` | additional §10 | Environment metadata on diagnostic events | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-011` | additional §11 | Deployment and revision correlation | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-012` | additional §12 | State snapshot references for serious faults | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-013` | additional §13 | Diagnostic bundles | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-014` | additional §14 | Known-fault catalog | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-015` | additional §15 | Recovery verification | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-016` | additional §16 | Fault obligations | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-017` | additional §17 | Acknowledged is not resolved | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-018` | additional §18 | Transient vs persistent classification | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-ADD-019` | additional §19 | Safe-mode support | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-020` | additional §20 | Startup fault boundary and bootstrap mode | done | Bootstrap.fs | BootstrapTests.fs |  |
| `AEG-ADD-021` | additional §21 | Shutdown fault boundary | done | Bootstrap.fs | BootstrapTests.fs |  |
| `AEG-ADD-022` | additional §22 | Unhandled top-level boundary | done | Capture.fs | Tests.fs |  |
| `AEG-ADD-023` | additional §23 | Integration contract tests for failure translation | done | Translation.fs, Aegis.Integration.GitHub | TranslationTests.fs |  |
| `AEG-ADD-024` | additional §24 | Schema migration awareness | done | Translation.fs, Aegis.Integration.GitHub | TranslationTests.fs |  |
| `AEG-ADD-025` | additional §25 | User notification policy via presentation intent | done | Presentation.fs | PresentationTests.fs |  |
| `AEG-ADD-026` | additional §26 | UI noise rate limiting | done | Presentation.fs | PresentationTests.fs |  |
| `AEG-ADD-027` | additional §27 | Privacy classification for context values | done | Redaction.fs | Tests.fs |  |
| `AEG-ADD-028` | additional §28 | Machine-remediation hooks | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-029` | additional §29 | Fault lifecycle model | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-030` | additional §30 | Fault immutability and event-based lifecycle changes | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-031` | additional §31 | Active fault projection derived from event history | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-032` | additional §32 | Explicit fault resolution | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-033` | additional §33 | Fault reopening | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-034` | additional §34 | Fault supersession | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-035` | additional §35 | Repeated transient fault behaviour | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-036` | additional §36 | Escalation as a lifecycle event | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-037` | additional §37 | Recordable recovery attempts | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-038` | additional §38 | Recovery actors | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-039` | additional §39 | Manual intervention representation | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-ADD-040` | additional §40 | Diagnostic export safety | done | Redaction.fs | Tests.fs |  |
| `AEG-ADD-041` | additional §41 | Fault searchability on structured fields | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-ADD-042` | additional §42 | Agent diagnostic guidance on known faults | done | Diagnostics.fs, Catalog.fs, Containment.fs | DiagnosticsTests.fs |  |
| `AEG-ADD-043` | additional §43 | Failure domains | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-ADD-044` | additional §44 | Blast-radius metadata | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-ADD-045` | additional §45 | Dependency relationships on faults | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-ADD-046` | additional §46 | Root-cause grouping | done | Lifecycle.fs, Escalation.fs | LifecycleTests.fs, PresentationTests.fs |  |
| `AEG-ADD-047` | additional §47 | Configuration validation at startup | done | Bootstrap.fs | BootstrapTests.fs |  |
| `AEG-ADD-048` | additional §48 | Sink capability metadata | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-ADD-049` | additional §49 | Graceful degradation of optional diagnostics | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-ADD-050` | additional §50 | Required vs optional sink requirement levels | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-ADD-051` | additional §51 | Aegis health projection | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-ADD-052` | additional §52 | Retention and aggregation interaction | partial | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs | retention intent is represented; enforcement belongs to an adapter outside this repository -- DF-AEGIS-2026-DBBD |
| `AEG-ADD-053` | additional §53 | Policy separation across concerns | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-ADD-054` | additional §54 | Architectural principle: own the failure lifecycle | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-CORE-000` | core §0 | Architectural rule: simpler failure handling without invisible failure | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-CORE-001` | core §1 | Purpose: standard mechanism for handling and recovering from unexpected faults | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-CORE-002` | core §2 | Core distinction between domain and operational failures | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-003` | core §3 | Standard fault model | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-004` | core §4 | Stable machine-readable fault codes | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-005` | core §5 | Deliberately small capture API | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-006` | core §6 | Use Aegis at architectural boundaries | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-007` | core §7 | No silent swallowing of faults | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-008` | core §8 | Recovery policy model | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-CORE-009` | core §9 | SDE integration: faults may propose transitions | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-CORE-010` | core §10 | Limen integration: standardized fault presentation model | done | Presentation.fs | PresentationTests.fs |  |
| `AEG-CORE-011` | core §11 | Separate user-facing, technical and diagnostic information | done | Redaction.fs | Tests.fs |  |
| `AEG-CORE-012` | core §12 | Explicit redaction rules for sensitive data | done | Redaction.fs | Tests.fs |  |
| `AEG-CORE-013` | core §13 | Structured fault context | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-014` | core §14 | Correlation IDs across related operations | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-015` | core §15 | Preserve fault causal chains | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-016` | core §16 | Translate low-level exceptions at integration boundaries | done | Translation.fs, Aegis.Integration.GitHub | TranslationTests.fs |  |
| `AEG-CORE-017` | core §17 | Preserve original exception information through translation | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-018` | core §18 | Standardized severity classifications | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-019` | core §19 | Programming defects fail loudly | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-020` | core §20 | Special treatment for data integrity faults | done | Translation.fs, Aegis.Integration.GitHub | TranslationTests.fs |  |
| `AEG-CORE-021` | core §21 | Retry only under explicit policy | done | Recovery.fs | RecoveryTests.fs |  |
| `AEG-CORE-022` | core §22 | Bounded in-memory fault history | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-CORE-023` | core §23 | Configurable fault sinks | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-CORE-024` | core §24 | Multiple simultaneous sinks | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-CORE-025` | core §25 | Aegis must survive its own failures | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-CORE-026` | core §26 | Configure Aegis once at initialization | done | Bootstrap.fs | BootstrapTests.fs |  |
| `AEG-CORE-027` | core §27 | Deterministic testability with replaceable sinks | done | (the suite itself) | CompatibilityTests.fs |  |
| `AEG-CORE-028` | core §28 | Unit-test coverage for the Aegis package | done | (the suite itself) | CompatibilityTests.fs |  |
| `AEG-CORE-029` | core §29 | Cancellation is not necessarily a fault | done | Capture.fs | Tests.fs |  |
| `AEG-CORE-030` | core §30 | Agent-readable structured diagnostics | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-CORE-031` | core §31 | Human-readable diagnostics derived from the same fault | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-CORE-032` | core §32 | Integration assembly responsibility and typed failure models | done | Translation.fs, Aegis.Integration.GitHub | TranslationTests.fs |  |
| `AEG-CORE-033` | core §33 | ROS integration: declared fault boundaries | partial | Sde.fs, aegis-boundaries.json, docs/aegis/ | BoundaryTests.fs | declaration + tests exist but ROS does not require or validate it |
| `AEG-CORE-034` | core §34 | Documentation requirement | done | Sde.fs, aegis-boundaries.json, docs/aegis/ | BoundaryTests.fs |  |
| `AEG-CORE-035` | core §35 | Dependency constraints | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-CORE-036` | core §36 | C# consumability | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-CORE-037` | core §37 | Schema version on serialized faults | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-038` | core §38 | Observability without telemetry dependency | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-CORE-039` | core §39 | Application availability impact model | done | Types.fs | FaultDiagnosticsTests.fs |  |
| `AEG-CORE-040` | core §40 | Close out initial-pass open design questions | done | Sde.fs, aegis-boundaries.json, docs/aegis/ | BoundaryTests.fs |  |
| `AEG-LOG-001` | logging §1 | Purpose: storage-independent persistence of faults and lifecycle events | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-LOG-002` | logging §2 | Standard sink abstraction | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-003` | logging §3 | Standard store abstraction | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-004` | logging §4 | Storage adapters outside the core | partial | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs | the GitHub adapter is the reference implementation; the rest are out of scope here -- DF-AEGIS-2026-DBBD |
| `AEG-LOG-005` | logging §5 | Persist more than faults: the lifecycle event model | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-006` | logging §6 | Append-oriented immutable storage | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-007` | logging §7 | GitHub storage model: one immutable file per event | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-008` | logging §8 | GitHub file naming with sortable unique identifiers | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-009` | logging §9 | GitHub repository configuration | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-010` | logging §10 | Database storage with efficient lookup | not started | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs | out of scope here: database adapters are built against `Store.T` elsewhere -- DF-AEGIS-2026-DBBD |
| `AEG-LOG-011` | logging §11 | Storage schema consistency across sinks | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-012` | logging §12 | Versioned event schema | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-013` | logging §13 | Standard serialized event shape | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-014` | logging §14 | Simultaneous logging to multiple sinks | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-015` | logging §15 | Sink independence on failure | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-016` | logging §16 | Bounded sink failure handling with re-entry guard | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-017` | logging §17 | Primary operation safety on persistence failure | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-018` | logging §18 | Asynchronous persistence | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-019` | logging §19 | Event batching | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-020` | logging §20 | Offline and deferred delivery | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-021` | logging §21 | Redaction before events reach any sink | done | Redaction.fs | Tests.fs |  |
| `AEG-LOG-022` | logging §22 | Consistent correlation across sinks | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-023` | logging §23 | Fault ID preserved on every lifecycle event | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-024` | logging §24 | Distinct event identity | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-025` | logging §25 | UTC timestamp requirements | done | Serialization.fs | LifecycleTests.fs |  |
| `AEG-LOG-026` | logging §26 | Retention policy metadata | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-027` | logging §27 | Provider-independent query model | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-028` | logging §28 | Recording path separate from querying | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-LOG-029` | logging §29 | Agent readability of persisted events | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-030` | logging §30 | Human readability without proprietary tooling | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-031` | logging §31 | Reconstructable audit history | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-032` | logging §32 | Idempotent writes | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-033` | logging §33 | Event ordering reconstruction | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-034` | logging §34 | Concurrent write tolerance | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-035` | logging §35 | GitHub commit strategy | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-036` | logging §36 | GitHub conflict handling | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-037` | logging §37 | Database transaction behaviour for batches | not started | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs | out of scope here: batch semantics are per adapter, documented by it -- DF-AEGIS-2026-DBBD |
| `AEG-LOG-038` | logging §38 | Sink health and diagnostics | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-039` | logging §39 | Declare sinks once in configuration | done | Bootstrap.fs | BootstrapTests.fs |  |
| `AEG-LOG-040` | logging §40 | Deterministic tests per sink implementation | done | (the suite itself) | CompatibilityTests.fs |  |
| `AEG-LOG-041` | logging §41 | In-memory test sink | done | Sinks.fs, Offline.fs, Health.fs | AsyncDeliveryTests.fs, SinkTypesTests.fs |  |
| `AEG-LOG-042` | logging §42 | Minimal core dependencies | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-LOG-043` | logging §43 | Integration assemblies may provide sinks | done | Store.fs, Aegis.Store.GitHub | GitHubStoreTests.fs |  |
| `AEG-LOG-044` | logging §44 | SDE integration for persistence state | partial | Sde.fs, aegis-boundaries.json, docs/aegis/ | BoundaryTests.fs | proposals exist; no SDE to consume them |
| `AEG-LOG-045` | logging §45 | Limen integration for persistence state | done | Presentation.fs | PresentationTests.fs |  |
| `AEG-LOG-046` | logging §46 | ROS integration for persistence declarations | done | Sde.fs, aegis-boundaries.json, docs/aegis/ | BoundaryTests.fs |  |
| `AEG-LOG-047` | logging §47 | Recommended architectural principle for persistence | done | (architectural constraints) | BoundaryTests.fs |  |
| `AEG-LOG-048` | logging §48 | Scope constraint on persistence | done | (architectural constraints) | BoundaryTests.fs |  |

## Regenerating this

The status column comes from an audit that inspects the codebase rather than
trusting a claim: whether the type exists, whether anything constructs or
consumes it, and whether a test exercises it. That audit is what found two
requirements marked complete with no code at all, and four more that existed
only as types nothing attached.

The counts are therefore a measurement. Earlier measurements in this
repository's history were 118 done / 19 partial / 6 not started before the
post-audit work, and 137 / 4 / 2 after it.
