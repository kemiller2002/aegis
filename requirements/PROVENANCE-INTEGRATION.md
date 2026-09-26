---
id: GV-AEGIS-006
title: Contribution provenance on faults and security findings
status: draft
version: 1.2.0
owners:
  - repository-governance
created: 2026-09-26
updated: 2026-09-26
related_documents:
  - research/decisions/DF-AEGIS-2026-DC5B--fault-contribution-provenance.md
  - docs/aegis/REQUIREMENTS-STATUS.md
  - requirements/TUTELA-INTEGRATION.md
  - tests/fixtures/praxis-provenance/SOURCE.json
tags: [aegis, provenance, security, praxis, interchange]
provenance:
  contributions:
    EXE-20260926T081020061Z-1e736e64:
      operations: [created]
      at: 2026-09-26T08:15:12.734Z
      actor:
        kind: agent
        id: anthropic/claude-code
        provider: anthropic
        model: unknown
        runtime: claude-code
      reason: "Echelon provenance upgrade for Aegis (FEAT-ECHELON-PROVENANCE)"
    EXE-20260926T090253922Z-bb95f3ce:
      operations: [modified]
      at: 2026-09-26T09:03:13.875Z
      actor:
        kind: agent
        id: anthropic/claude-code
        provider: anthropic
        model: unknown
        runtime: claude-code
      reason: "Apply Praxis provenance contract revision 1.1 and review findings (FEAT-ECHELON-PROVENANCE-R2)"
    EXE-20260926T204110318Z-32ff901f:
      operations: [modified]
      at: 2026-09-26T20:49:15.941Z
      actor:
        kind: agent
        id: anthropic/claude-code
        provider: anthropic
        model: unknown
        runtime: claude-code
      reason: "Apply Praxis provenance contract revision 1.2 and second-review findings (FEAT-ECHELON-PROVENANCE-R12)"
---

# Contribution provenance on faults and security findings

Aegis records *who or what* discovered, remediated, validated, acknowledged,
escalated, reopened or superseded a fault, and *in which execution*, so that
security outcomes can later be compared by agent and by execution.

Aegis does not define that model. The actor, execution, contribution, lineage
and "unknown" semantics are Praxis's
(`kemiller2002/praxis` `docs/agent-provenance.md`, decisions
`DF-ROS-2026-A036` and `DF-ROS-2026-A037`, requirements
`RQ-ROS-2026-A001`..`A019`). Aegis carries the Praxis interchange block
`praxis.provenance/1` and applies Praxis's receiving and appending rules. The
decision for Aegis's side is
[`DF-AEGIS-2026-DC5B`](../research/decisions/DF-AEGIS-2026-DC5B--fault-contribution-provenance.md).

Traceability (implementation and tests) is in
[`docs/aegis/REQUIREMENTS-STATUS.md`](../docs/aegis/REQUIREMENTS-STATUS.md),
section "Contribution provenance".

## Requirements

- **AEG-PROV-001 -- Events carry the interchange block.** Any Aegis event,
  including the one that records a fault, MAY carry one `praxis.provenance/1`
  block, serialized under the event's `provenance` field. The block is
  optional; the event schema stays `aegis/event/v1` and the fault schema
  `aegis/fault/v1`. (RQ-ROS-2026-A009, RQ-ROS-2026-A015; DF-ROS-2026-A037 §1)

- **AEG-PROV-002 -- Discovering actor and execution.** The event that records
  a fault or security finding carries the discovering contribution: operations
  `created` and `discovered`, keyed by the discovering execution (`EXE-...`
  for a Praxis execution, `EXT-<system>.<run-id>` for another Echelon system,
  `EXT-op.<operationId>` when only an operation is known, `CTB-...` for a
  non-agent contributor outside any execution). Two executions of one agent
  are two keys and never merge. (RQ-ROS-2026-A001, A002, A013, A014)

- **AEG-PROV-003 -- Later contributors live on later events.** Stored events
  are immutable, so a later contribution is carried by the lifecycle event that
  records it: a recovery attempt carries `remediated`; a verified resolution
  or verification carries `validated` (and `resolved` where the same actor
  resolved it); acknowledgement carries `reviewed`; escalation and reopening
  carry `modified`; supersession carries `superseded`; each with its own actor
  and execution when known. `RecoveryActor` remains a role category
  (User/Application/Agent/...), never an identity. (RQ-ROS-2026-A003, A004,
  A014)

- **AEG-PROV-004 -- Accumulated provenance is a pure projection.** A pure
  fold over one fault's event stream yields the fault's accumulated block by
  appending each event's contributions with Praxis's rules: same key merges
  operations and advances `last` only when the actor agrees; no
  re-attribution; no second or late `created`; nothing deleted, reordered or
  rewritten; unknown fields kept, including unknown top-level fields of each
  event's block (such as `subject`), where the earliest value wins and a
  differing later value is reported as a conflict. A contribution the fold
  refuses is reported as a conflict, never silently dropped. (RQ-ROS-2026-A004)

- **AEG-PROV-005 -- Affected-artifact lineage is not authorship.** The
  artifacts a finding concerns (a Git commit, a file, a Praxis artifact, a
  record in another system) are recorded in `derivedFrom` with namespaced
  references (`git:commit/<sha>`, `aegis:fault/<id>`, `praxis:RQ-...`),
  separate from contributions. Lineage never contributes authors. Lineage is
  checked like contributions (contract revision 1.2): the block must be
  supported, every reference non-blank, well-formed Unicode and
  credential-free, duplicates are dropped keeping the first, and the result
  must classify as supported. A refusal is an error; lineage is never dropped
  silently. (RQ-ROS-2026-A008; DF-ROS-2026-A037 revision 1.2)

- **AEG-PROV-006 -- Evidence provenance.** The diagnostic material that
  supports a discovery (environment metadata, snapshot reference, breadcrumb
  trail) is referenced from the discovering contribution's `evidence` list by
  reference, never by value, so no context or payload enters provenance.
  (RQ-ROS-2026-A004, A017)

- **AEG-PROV-007 -- Receiving rules.** Every block is classified before Aegis
  accepts it: `supported` (kept with unknown fields and tolerated unknown
  operations), `unsupported` (another major version: stored and serialized
  verbatim, never merged into), `malformed` (rejected with a clear error when
  the block is built, attached or appended, never repaired or dropped).
  Credential-like values anywhere make a block malformed. Serialization writes
  the block verbatim. Praxis contract revision 1.1 applies: exact matching
  (no trailing newline in keys, codes, kinds or tags), calendar-valid
  timestamps ordered at millisecond precision, `null` is never absence, an
  append never returns a block that would classify as anything but
  supported, a same-key merge keeps incoming unknown fields and the later
  `last` and refuses an unknown actor extending a known one, and
  operation-derived keys are escaped injectively. Praxis contract revision
  1.2 also applies: provenance is read as JSON text, and text that is not
  JSON, repeats a member name within any one object, or holds an unpaired
  UTF-16 surrogate is malformed whatever its major version; `classify` and
  `receive` never throw; "blank" means empty after trimming ASCII whitespace
  only, and credential patterns use explicit ASCII classes; key segments are
  escaped per Unicode code point, with everything but ASCII letters, digits
  and `-` (so `.` and `_` too) becoming `_xx` per UTF-8 byte, and an id that
  is empty or not well-formed Unicode cannot form a key. Redaction rules are
  key-name rules: a block whose field name (other than a contribution key)
  matches one of the application's redaction rules is rejected when attached
  or reported, never redacted in place; free-text values get the contract
  credential check instead, so an ordinary finding ("Session cookie lacks the
  Secure flag") is accepted and a real token is not. The serializer refuses
  to write a matching block and records `provenanceRejected` instead.
  (RQ-ROS-2026-A015, A017; DF-ROS-2026-A037 revisions 1.1 and 1.2)

- **AEG-PROV-008 -- Legacy events stay valid and unattributed.** Events
  written before this capability, and events without a block, remain valid and
  read as *unattributed*. Aegis never backfills or infers historical actors.
  An event written with `provenanceRejected` reads back as rejected, with its
  reason, never as unattributed; a stored `"provenance": null` is malformed,
  not absent. (RQ-ROS-2026-A004, A007; DF-ROS-2026-A037 revision 1.2)

- **AEG-PROV-009 -- Tutela projection carries contribution provenance.** The
  Tutela evidence projection of a security finding MAY carry the fault's
  accumulated block under `contributionProvenance`. It never reuses Tutela's
  `provenance` (issuer/run attestation) and never presents self-reported
  identity as `producerIdentity`, authentication, authorization or evidence
  weight. (RQ-ROS-2026-A010, A019; requirements/TUTELA-INTEGRATION.md)

- **AEG-PROV-010 -- Explicit identity propagation.** The current actor and
  execution come only from explicit declarations (`ROS_ACTOR_KIND`,
  `ROS_ACTOR`, `ROS_TELEMETRY_PROVIDER`, `ROS_TELEMETRY_MODEL`,
  `ROS_TELEMETRY_RUNTIME`, `ROS_EXECUTION_ID`, or values the caller passes).
  Anything undeclared is recorded as `unknown`; nothing is guessed and Praxis
  need not be installed. `ROS_EXECUTION_ID` is honoured only when the process
  also declares a kind or an id, so an identity-less process (for example a
  service started from an agent's shell) never inherits that agent's run.
  Discovery reads only variables in the vendored
  `identity-environment.json`. (RQ-ROS-2026-A006, A016)

- **AEG-PROV-011 -- Conformance to the shared fixtures.** Aegis's codec
  reaches the same verdict and warning count as the Praxis reference library
  on every vendored `cases.json` case, replays the vendored
  `echelon-chain.json` finding `aegis:finding/SF-0001` with the expected
  discovered/remediated/validated roles, reaches the reference verdict on
  every `text-cases.json` case and the reference result on every
  `lineage-cases.json` case, derives every `envelope-key-cases.json` key
  with its key-segment escaping, and a test detects any local edit to the
  vendored fixtures by SHA-256. (RQ-ROS-2026-A018)

- **AEG-PROV-012 -- Backward compatibility.** The capability is additive:
  no existing public record, union case or function signature changes, the C#
  consumability surface keeps compiling, and existing consumers of
  `EchelonFoundry.Aegis.Core` 1.0.0 (including Praxis) are unaffected. The
  provenance surface itself is unreleased, so revision 1.2 may change it:
  `Provenance.escapeKeySegment`, `Provenance.operationKey` and
  `ProvenanceIdentity.keyFor` now return `Result`, and `FaultProvenance`
  gains `Rejected`. (AEG-CORE-036, AEG-CORE-037, AEG-LOG-012)

## Revision notes

- **1.2.0 (2026-09-26, FEAT-ECHELON-PROVENANCE-R12).** Praxis contract
  revision 1.2 (Praxis `b003718`) and the second adversarial review.
  AEG-PROV-007: text-level well-formedness (duplicate member names, unpaired
  surrogates), `classify`/`receive` never throw, ASCII whitespace and
  credential semantics, per-code-point key escaping including `.`, and
  redaction rules applied to field names only with the credential check for
  values (review finding 8). AEG-PROV-005: lineage is checked. AEG-PROV-004:
  unknown top-level fields survive the fold. AEG-PROV-008: `provenanceRejected`
  is distinguishable on read; a stored `null` is malformed. AEG-PROV-011: the
  new text, lineage and envelope-key fixtures. AEG-PROV-012: note on the
  unreleased provenance surface.
- **1.1.0 (2026-09-26, FEAT-ECHELON-PROVENANCE-R2).** Praxis contract
  revision 1.1 and the first review's findings.
- **1.0.0 (2026-09-26, FEAT-ECHELON-PROVENANCE).** Initial requirements.
