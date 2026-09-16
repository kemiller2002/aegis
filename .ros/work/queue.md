# Work Queue

| ID | Work | Status | Tags | Priority |
|---|---|---|---|---|
| AEG-ADD-001 | Fault scopes establishing shared diagnostic context | captured | requirement, aegis-additional, context | high |
| AEG-ADD-002 | Bounded breadcrumb trail | captured | requirement, aegis-additional, diagnostics | medium |
| AEG-ADD-003 | Fault deduplication | captured | requirement, aegis-additional, aggregation | high |
| AEG-ADD-004 | Stable fault fingerprints | captured | requirement, aegis-additional, aggregation | high |
| AEG-ADD-005 | Policy-driven escalation rules | captured | requirement, aegis-additional, escalation | medium |
| AEG-ADD-006 | Expose fault state for circuit-breaker adapters | captured | requirement, aegis-additional, resilience | low |
| AEG-ADD-007 | Quarantine support for unprocessable data | captured | requirement, aegis-additional, quarantine | medium |
| AEG-ADD-008 | Dead-letter handling | captured | requirement, aegis-additional, quarantine | medium |
| AEG-ADD-009 | Fault ownership by subsystem | captured | requirement, aegis-additional, model | medium |
| AEG-ADD-010 | Environment metadata on diagnostic events | captured | requirement, aegis-additional, metadata | medium |
| AEG-ADD-011 | Deployment and revision correlation | captured | requirement, aegis-additional, metadata | medium |
| AEG-ADD-012 | State snapshot references for serious faults | captured | requirement, aegis-additional, diagnostics | medium |
| AEG-ADD-013 | Diagnostic bundles | captured | requirement, aegis-additional, diagnostics | medium |
| AEG-ADD-014 | Known-fault catalog | captured | requirement, aegis-additional, catalog | medium |
| AEG-ADD-015 | Recovery verification | captured | requirement, aegis-additional, recovery | high |
| AEG-ADD-016 | Fault obligations | captured | requirement, aegis-additional, obligations | high |
| AEG-ADD-017 | Acknowledged is not resolved | captured | requirement, aegis-additional, lifecycle | high |
| AEG-ADD-018 | Transient vs persistent classification | captured | requirement, aegis-additional, model | high |
| AEG-ADD-019 | Safe-mode support | captured | requirement, aegis-additional, safe-mode | high |
| AEG-ADD-020 | Startup fault boundary and bootstrap mode | captured | requirement, aegis-additional, bootstrap | high |
| AEG-ADD-021 | Shutdown fault boundary | captured | requirement, aegis-additional, lifecycle | medium |
| AEG-ADD-022 | Unhandled top-level boundary | captured | requirement, aegis-additional, boundaries | high |
| AEG-ADD-023 | Integration contract tests for failure translation | captured | requirement, aegis-additional, testing | high |
| AEG-ADD-024 | Schema migration awareness | captured | requirement, aegis-additional, schema | high |
| AEG-ADD-025 | User notification policy via presentation intent | captured | requirement, aegis-additional, presentation | high |
| AEG-ADD-026 | UI noise rate limiting | captured | requirement, aegis-additional, presentation | medium |
| AEG-ADD-027 | Privacy classification for context values | captured | requirement, aegis-additional, privacy | high |
| AEG-ADD-028 | Machine-remediation hooks | captured | requirement, aegis-additional, automation | high |
| AEG-ADD-029 | Fault lifecycle model | captured | requirement, aegis-additional, lifecycle | high |
| AEG-ADD-030 | Fault immutability and event-based lifecycle changes | captured | requirement, aegis-additional, lifecycle | high |
| AEG-ADD-031 | Active fault projection derived from event history | captured | requirement, aegis-additional, lifecycle | high |
| AEG-ADD-032 | Explicit fault resolution | captured | requirement, aegis-additional, lifecycle | high |
| AEG-ADD-033 | Fault reopening | captured | requirement, aegis-additional, lifecycle | medium |
| AEG-ADD-034 | Fault supersession | captured | requirement, aegis-additional, lifecycle | medium |
| AEG-ADD-035 | Repeated transient fault behaviour | captured | requirement, aegis-additional, aggregation | medium |
| AEG-ADD-036 | Escalation as a lifecycle event | captured | requirement, aegis-additional, escalation | medium |
| AEG-ADD-037 | Recordable recovery attempts | captured | requirement, aegis-additional, recovery | high |
| AEG-ADD-038 | Recovery actors | captured | requirement, aegis-additional, recovery | medium |
| AEG-ADD-039 | Manual intervention representation | captured | requirement, aegis-additional, obligations | high |
| AEG-ADD-040 | Diagnostic export safety | captured | requirement, aegis-additional, privacy | high |
| AEG-ADD-041 | Fault searchability on structured fields | captured | requirement, aegis-additional, query | high |
| AEG-ADD-042 | Agent diagnostic guidance on known faults | captured | requirement, aegis-additional, automation | medium |
| AEG-ADD-043 | Failure domains | captured | requirement, aegis-additional, model | medium |
| AEG-ADD-044 | Blast-radius metadata | captured | requirement, aegis-additional, model | medium |
| AEG-ADD-045 | Dependency relationships on faults | captured | requirement, aegis-additional, model | medium |
| AEG-ADD-046 | Root-cause grouping | captured | requirement, aegis-additional, aggregation | medium |
| AEG-ADD-047 | Configuration validation at startup | captured | requirement, aegis-additional, configuration | high |
| AEG-ADD-048 | Sink capability metadata | captured | requirement, aegis-additional, sinks | medium |
| AEG-ADD-049 | Graceful degradation of optional diagnostics | captured | requirement, aegis-additional, resilience | high |
| AEG-ADD-050 | Required vs optional sink requirement levels | captured | requirement, aegis-additional, sinks | high |
| AEG-ADD-051 | Aegis health projection | captured | requirement, aegis-additional, health | medium |
| AEG-ADD-052 | Retention and aggregation interaction | captured | requirement, aegis-additional, retention | medium |
| AEG-ADD-053 | Policy separation across concerns | captured | requirement, aegis-additional, principle | high |
| AEG-ADD-054 | Architectural principle: own the failure lifecycle | captured | requirement, aegis-additional, principle | high |
| AEG-CORE-000 | Architectural rule: simpler failure handling without invisible failure | captured | requirement, aegis-core, principle | high |
| AEG-CORE-001 | Purpose: standard mechanism for handling and recovering from unexpected faults | captured | requirement, aegis-core, purpose | high |
| AEG-CORE-002 | Core distinction between domain and operational failures | captured | requirement, aegis-core, model | high |
| AEG-CORE-003 | Standard fault model | captured | requirement, aegis-core, model | high |
| AEG-CORE-004 | Stable machine-readable fault codes | captured | requirement, aegis-core, model | high |
| AEG-CORE-005 | Deliberately small capture API | captured | requirement, aegis-core, api | high |
| AEG-CORE-006 | Use Aegis at architectural boundaries | captured | requirement, aegis-core, boundaries | high |
| AEG-CORE-007 | No silent swallowing of faults | captured | requirement, aegis-core, policy | high |
| AEG-CORE-008 | Recovery policy model | captured | requirement, aegis-core, recovery | high |
| AEG-CORE-009 | SDE integration: faults may propose transitions | captured | requirement, aegis-core, integration-sde | high |
| AEG-CORE-010 | Limen integration: standardized fault presentation model | captured | requirement, aegis-core, integration-limen | high |
| AEG-CORE-011 | Separate user-facing, technical and diagnostic information | captured | requirement, aegis-core, privacy | high |
| AEG-CORE-012 | Explicit redaction rules for sensitive data | captured | requirement, aegis-core, privacy | high |
| AEG-CORE-013 | Structured fault context | captured | requirement, aegis-core, context | high |
| AEG-CORE-014 | Correlation IDs across related operations | captured | requirement, aegis-core, correlation | high |
| AEG-CORE-015 | Preserve fault causal chains | captured | requirement, aegis-core, model | medium |
| AEG-CORE-016 | Translate low-level exceptions at integration boundaries | captured | requirement, aegis-core, translation | high |
| AEG-CORE-017 | Preserve original exception information through translation | captured | requirement, aegis-core, translation | high |
| AEG-CORE-018 | Standardized severity classifications | captured | requirement, aegis-core, model | medium |
| AEG-CORE-019 | Programming defects fail loudly | captured | requirement, aegis-core, policy | high |
| AEG-CORE-020 | Special treatment for data integrity faults | captured | requirement, aegis-core, data-integrity | high |
| AEG-CORE-021 | Retry only under explicit policy | captured | requirement, aegis-core, recovery | high |
| AEG-CORE-022 | Bounded in-memory fault history | captured | requirement, aegis-core, history | medium |
| AEG-CORE-023 | Configurable fault sinks | captured | requirement, aegis-core, sinks | high |
| AEG-CORE-024 | Multiple simultaneous sinks | captured | requirement, aegis-core, sinks | high |
| AEG-CORE-025 | Aegis must survive its own failures | captured | requirement, aegis-core, resilience | high |
| AEG-CORE-026 | Configure Aegis once at initialization | captured | requirement, aegis-core, configuration | high |
| AEG-CORE-027 | Deterministic testability with replaceable sinks | captured | requirement, aegis-core, testing | high |
| AEG-CORE-028 | Unit-test coverage for the Aegis package | captured | requirement, aegis-core, testing | high |
| AEG-CORE-029 | Cancellation is not necessarily a fault | captured | requirement, aegis-core, policy | medium |
| AEG-CORE-030 | Agent-readable structured diagnostics | captured | requirement, aegis-core, diagnostics | high |
| AEG-CORE-031 | Human-readable diagnostics derived from the same fault | captured | requirement, aegis-core, diagnostics | high |
| AEG-CORE-032 | Integration assembly responsibility and typed failure models | captured | requirement, aegis-core, integration | high |
| AEG-CORE-033 | ROS integration: declared fault boundaries | captured | requirement, aegis-core, integration-ros | low |
| AEG-CORE-034 | Documentation requirement | captured | requirement, aegis-core, documentation | high |
| AEG-CORE-035 | Dependency constraints | captured | requirement, aegis-core, constraints | high |
| AEG-CORE-036 | C# consumability | captured | requirement, aegis-core, constraints | medium |
| AEG-CORE-037 | Schema version on serialized faults | captured | requirement, aegis-core, schema | high |
| AEG-CORE-038 | Observability without telemetry dependency | captured | requirement, aegis-core, constraints | high |
| AEG-CORE-039 | Application availability impact model | captured | requirement, aegis-core, model | high |
| AEG-CORE-040 | Close out initial-pass open design questions | captured | requirement, aegis-core, traceability | medium |
| AEG-LOG-001 | Purpose: storage-independent persistence of faults and lifecycle events | captured | requirement, aegis-logging, purpose | high |
| AEG-LOG-002 | Standard sink abstraction | captured | requirement, aegis-logging, sinks | high |
| AEG-LOG-003 | Standard store abstraction | captured | requirement, aegis-logging, storage | high |
| AEG-LOG-004 | Storage adapters outside the core | captured | requirement, aegis-logging, storage | high |
| AEG-LOG-005 | Persist more than faults: the lifecycle event model | captured | requirement, aegis-logging, model, lifecycle | high |
| AEG-LOG-006 | Append-oriented immutable storage | captured | requirement, aegis-logging, storage | high |
| AEG-LOG-007 | GitHub storage model: one immutable file per event | captured | requirement, aegis-logging, github | high |
| AEG-LOG-008 | GitHub file naming with sortable unique identifiers | captured | requirement, aegis-logging, github | high |
| AEG-LOG-009 | GitHub repository configuration | captured | requirement, aegis-logging, github | high |
| AEG-LOG-010 | Database storage with efficient lookup | captured | requirement, aegis-logging, database | high |
| AEG-LOG-011 | Storage schema consistency across sinks | captured | requirement, aegis-logging, schema | high |
| AEG-LOG-012 | Versioned event schema | captured | requirement, aegis-logging, schema | high |
| AEG-LOG-013 | Standard serialized event shape | captured | requirement, aegis-logging, schema, model | high |
| AEG-LOG-014 | Simultaneous logging to multiple sinks | captured | requirement, aegis-logging, sinks | high |
| AEG-LOG-015 | Sink independence on failure | captured | requirement, aegis-logging, sinks | high |
| AEG-LOG-016 | Bounded sink failure handling with re-entry guard | captured | requirement, aegis-logging, resilience | high |
| AEG-LOG-017 | Primary operation safety on persistence failure | captured | requirement, aegis-logging, policy | high |
| AEG-LOG-018 | Asynchronous persistence | captured | requirement, aegis-logging, performance | high |
| AEG-LOG-019 | Event batching | captured | requirement, aegis-logging, performance | medium |
| AEG-LOG-020 | Offline and deferred delivery | captured | requirement, aegis-logging, offline | high |
| AEG-LOG-021 | Redaction before events reach any sink | captured | requirement, aegis-logging, privacy | high |
| AEG-LOG-022 | Consistent correlation across sinks | captured | requirement, aegis-logging, correlation | high |
| AEG-LOG-023 | Fault ID preserved on every lifecycle event | captured | requirement, aegis-logging, correlation | high |
| AEG-LOG-024 | Distinct event identity | captured | requirement, aegis-logging, model | high |
| AEG-LOG-025 | UTC timestamp requirements | captured | requirement, aegis-logging, model | high |
| AEG-LOG-026 | Retention policy metadata | captured | requirement, aegis-logging, retention | medium |
| AEG-LOG-027 | Provider-independent query model | captured | requirement, aegis-logging, query | high |
| AEG-LOG-028 | Recording path separate from querying | captured | requirement, aegis-logging, principle | high |
| AEG-LOG-029 | Agent readability of persisted events | captured | requirement, aegis-logging, diagnostics | high |
| AEG-LOG-030 | Human readability without proprietary tooling | captured | requirement, aegis-logging, diagnostics | medium |
| AEG-LOG-031 | Reconstructable audit history | captured | requirement, aegis-logging, audit | high |
| AEG-LOG-032 | Idempotent writes | captured | requirement, aegis-logging, storage | high |
| AEG-LOG-033 | Event ordering reconstruction | captured | requirement, aegis-logging, storage | high |
| AEG-LOG-034 | Concurrent write tolerance | captured | requirement, aegis-logging, concurrency | high |
| AEG-LOG-035 | GitHub commit strategy | captured | requirement, aegis-logging, github | medium |
| AEG-LOG-036 | GitHub conflict handling | captured | requirement, aegis-logging, github | high |
| AEG-LOG-037 | Database transaction behaviour for batches | captured | requirement, aegis-logging, database | high |
| AEG-LOG-038 | Sink health and diagnostics | captured | requirement, aegis-logging, health | medium |
| AEG-LOG-039 | Declare sinks once in configuration | captured | requirement, aegis-logging, configuration | high |
| AEG-LOG-040 | Deterministic tests per sink implementation | captured | requirement, aegis-logging, testing | high |
| AEG-LOG-041 | In-memory test sink | captured | requirement, aegis-logging, testing | high |
| AEG-LOG-042 | Minimal core dependencies | captured | requirement, aegis-logging, constraints | high |
| AEG-LOG-043 | Integration assemblies may provide sinks | captured | requirement, aegis-logging, integration | medium |
| AEG-LOG-044 | SDE integration for persistence state | captured | requirement, aegis-logging, integration-sde | medium |
| AEG-LOG-045 | Limen integration for persistence state | captured | requirement, aegis-logging, integration-limen | medium |
| AEG-LOG-046 | ROS integration for persistence declarations | captured | requirement, aegis-logging, integration-ros | low |
| AEG-LOG-047 | Recommended architectural principle for persistence | captured | requirement, aegis-logging, principle | high |
| AEG-LOG-048 | Scope constraint on persistence | captured | requirement, aegis-logging, principle, constraints | high |
| REQ-INTAKE-001 | Attribute pre-ROS Aegis requirements documents | complete | documentation, attribution | medium |
| ROS-INSTALL-3-0-0 | ROS-INSTALL-3-0-0 | complete |  |  |
| SDE-INSTALL-1-2-0 | Install SDE 1.2.0 method documentation | complete | sde, scaffold | medium |
