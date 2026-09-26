---
id: DF-AEGIS-2026-7A1C
title: Security-finding provenance as an additive evolution of aegis/fault/v1 and aegis/event/v1
status: accepted
version: 1.0.0
created: 2026-09-26
updated: 2026-09-26
owners:
  - repository-governance
tags: [aegis, provenance, schema, versioning, privacy, tutela]
related_documents:
  - docs/aegis/REQUIREMENTS-STATUS.md
  - research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md
  - Input-documents/aegis_persistent_logging_requirements.txt
  - Input-documents/aegis_additional_requirements_and_design_ideas.txt
  - tests/Aegis.Core.Tests/fixtures/praxis-provenance-record/SOURCE.json
supersedes: []
superseded_by: []
---

# Decision Record: security-finding provenance

**Status: accepted.** Implements `AEG-PROV-001` to `AEG-PROV-007` (work item
`AEG-SLICE-015`). The contract is owned by Praxis: `RQ-ROS-2026-A001` (actor),
`A004` (contribution history), `A013` (interchange record), `A014` (execution
propagation), `A015` (no silent stripping), and `DF-ROS-2026-A037`. This record
decides how Aegis adopts that contract. It does not restate it.

## Context

A security-classified fault is the finding that Aegis projects to Tutela.
Security outcomes will later be compared by agent and by execution. That
comparison needs the following for each finding:

- who discovered it, and in which run;
- which affected artifacts it derives from (lineage);
- its evidence references;
- every later contributor, including the remediation actor and the
  validation actor.

Aegis recorded none of this. `RecoveryActor` is a category with no identity.
`Resolution` has no resolver. Only `FaultAcknowledged` names an actor, and
only as a category.

Three constraints shaped the decision:

- **Compatibility.** The public API (F# and C#) and the serialized payloads
  have consumers. Logging 12 says schema evolution must not silently break
  existing consumers, agents, tools or historical records.
- **Dependencies.** The core takes no third-party dependency (core 35, logging
  42). It must also not depend on Praxis.
- **Privacy.** Additional 38 says actor metadata should not require
  identifying a specific individual unless that is necessary.

## Decision

1. **Stay on `aegis/fault/v1` and `aegis/event/v1`, and add three optional
   members.** The members are `attribution` (who performed the event, and in
   which execution), `validatedBy` (who verified a resolution or a succeeded
   recovery), and `provenance` (the fault's Praxis interchange record, carried
   verbatim). They are written after every existing member, and only when
   supplied.
   - This follows the repository's own versioning rule. Logging 12 forbids
     *breaking* consumers, not *extending* the payload.
   - `CompatibilityTests` already require readers to tolerate unknown fields
     ("an event carrying unknown future fields is still readable"), and
     `Store.index` ignores them.
   - `docs/work-protocol.md` classes additive fields as compatible and
     reserves a new major for breaking semantic changes.
   - No existing member changes name, type, order or meaning. A payload
     without provenance is byte-identical to the one written before; the
     golden pins in `CompatibilityTests` prove it.
   - A `v2` would force every reader to handle two identifiers for the same
     meaning. It would buy nothing.
   - A new major is reserved for the day an existing member must change.

2. **Add the new APIs instead of changing signatures.**
   - `AegisEvent` cases, `Fault`, `Resolution`, `RecoveryAttempt`,
     `Store.Indexed` and `Tutela.Evidence` are unchanged.
   - New entry points: `Serialization.eventWith` / `faultWith` taking a
     `Serialization.Options` record, `Aegis.reportWith`,
     `Store.attributions` / `Store.provenance`,
     `Tutela.tryProjectFaultAttributed`, and `Sinks.deliverPayloadAsync`.
   - Adding a case or a field would break exhaustive matches and positional
     construction in consumers, including C#.
   - `RecoveryActor` stays as the *category* of recovery initiator
     (additional 38). The Praxis actor is the *identity*. The two coexist.

3. **Implement a small local codec (`Provenance.fs`, BCL `System.Text.Json`
   only).**
   - It holds the Praxis actor, attribution, contribution and interchange
     record, keeping the JSON identical to the contract. The actor's keys are
     always written in the order `kind,id,provider,model,runtime`.
   - A record is held as its verbatim text plus how it read (`Document`).
     Unknown fields at every level therefore survive, and an unsupported
     major is carried but never extended.
   - Malformed provenance cannot become a `Document`. It is rejected, never
     dropped.
   - Execution keys:
     - `ROS_EXECUTION_ID` is used when Praxis propagates it;
     - otherwise Aegis keys its own run as `EXE-aegis.<run>`;
     - otherwise `CTB-<ref>` for a human or automation outside any run.
   - Aegis never mints a Praxis-shaped `EXE-<timestamp>-<random>`.

4. **Lifecycle operations become contributions, append-only.**
   `Document.advance` maps each Aegis event to documented operations:

   | Aegis event | Operation |
   |---|---|
   | acknowledged | `x-handled` |
   | recovery concluded, succeeded or awaiting verification | `x-remediated` (remediation actor) |
   | verified resolution, or succeeded recovery, with `validatedBy` | `x-validated` (validation actor) |
   | resolved | `x-resolved` |
   | resolved, no longer applies | `x-dismissed` |
   | escalated | `modified` |
   | superseded | `superseded` |
   | reopened | `x-reopened` |

   - `x-reopened` is Aegis's own extension. Reopening is not a synonym of any
     documented operation, so it is namespaced rather than forced onto one
     that means something else.
   - The discoverer is the single `created` contribution, written by
     `Document.discovered`.
   - Every append passes the Praxis successor check before it is returned.
     The conformance test applies these operations to Praxis's `05` finding
     and obtains exactly Praxis's `10` record.

5. **Privacy (additional 38).**
   - A human actor's id is written as the existing redaction placeholder
     (`[redacted]`) unless the caller marks the attribution `identified`.
   - Agents and automation are not individuals and are always identified.
   - The rule is applied wherever Aegis writes an actor: events, appended
     contributions and Tutela.
   - A record Aegis only transports is carried verbatim. Rewriting another
     contributor's entry would violate `RQ-ROS-2026-A015`.
   - Credential-shaped values are refused in actor fields, reasons, evidence
     and lineage, so they can never be serialized.

6. **Tutela.** `tryProjectFaultAttributed` returns the unchanged evidence plus
   `ReportedBy`, which is present only when an attribution was supplied. It
   also adds a limitation stating that identity is self-reported provenance,
   not authorization, evidence or evidence weight.

## Consequences

- Existing consumers and stored events are unaffected. A consumer that wants
  provenance opts in through the new functions.
- `Store.attributions` and `Store.provenance` make "outcomes by agent and
  execution" queryable from stored payloads without changing the index
  record.
- The vendored fixtures pin Praxis commit `58cf46a` by SHA-256. Refreshing
  them is a deliberate act: update `SOURCE.json` and run the suite.
- **Known limit.** The lifecycle projection (`Lifecycle.Projected`) does not
  fold attributions. Attribution is read from payloads and records rather than
  from the in-memory projection.
- **Known limit.** A human's withheld id cannot be linked across events. That
  is the intended privacy trade-off. A caller that needs linkage marks the
  attribution `identified`.
- **Reversible.** The members are optional. Removing the new functions would
  leave every v1 payload valid.
