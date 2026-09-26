---
id: DF-AEGIS-2026-DC5B
title: Fault contribution provenance carries the Praxis interchange block
status: accepted
version: 1.1.0
created: 2026-09-26
updated: 2026-09-26
owners:
  - repository-governance
tags: [aegis, provenance, security, praxis, interchange, tutela]
related_documents:
  - requirements/PROVENANCE-INTEGRATION.md
  - docs/aegis/REQUIREMENTS-STATUS.md
  - requirements/TUTELA-INTEGRATION.md
  - tests/fixtures/praxis-provenance/SOURCE.json
supersedes: []
superseded_by: []
provenance:
  contributions:
    EXE-20260926T081020061Z-1e736e64:
      operations: [created]
      at: 2026-09-26T08:15:13.531Z
      actor:
        kind: agent
        id: anthropic/claude-code
        provider: anthropic
        model: unknown
        runtime: claude-code
      reason: "Echelon provenance upgrade for Aegis (FEAT-ECHELON-PROVENANCE)"
    EXE-20260926T090253922Z-bb95f3ce:
      operations: [modified]
      at: 2026-09-26T09:03:14.902Z
      actor:
        kind: agent
        id: anthropic/claude-code
        provider: anthropic
        model: unknown
        runtime: claude-code
      reason: "Apply Praxis provenance contract revision 1.1 and review findings (FEAT-ECHELON-PROVENANCE-R2)"
---

# Decision Record: fault contribution provenance

**Status: accepted.** Part of the Echelon provenance upgrade
(work item `FEAT-ECHELON-PROVENANCE`). Implements Praxis `DF-ROS-2026-A037`
for Aegis; requirements `AEG-PROV-001`..`AEG-PROV-012`
([`requirements/PROVENANCE-INTEGRATION.md`](../../requirements/PROVENANCE-INTEGRATION.md)).

## Context

Security findings are Aegis faults with `Category = SecurityFailure`, projected
to Tutela evidence. To compare security outcomes by agent and by execution,
a finding must keep who discovered it and in which run, which artifacts it
concerns, what evidence supported it, and who later remediated, validated,
acknowledged, escalated, reopened or superseded it.

Aegis had only fragments: `Fault.Owner` (a subsystem), `RecoveryActor` (a role
category with no identity), `FaultAcknowledged by: RecoveryActor`, and no actor
at all on resolution, escalation, reopening or supersession. Praxis
(`DF-ROS-2026-A036`, `DF-ROS-2026-A037`, `RQ-ROS-2026-A001`..`A019`) now owns
the one identity and provenance model for Echelon and a versioned interchange
block, `praxis.provenance/1`.

Constraints specific to Aegis:

- Stored events are immutable; lifecycle changes are new events
  (`AEG-ADD-030`).
- `EchelonFoundry.Aegis.Core` 1.0.0 is published and consumed (Praxis uses
  it). F# records gain no field without breaking every consumer that constructs
  them, and a new `AegisEvent` case breaks every exhaustive match compiled with
  warnings as errors.
- The core takes no third-party dependency (`AEG-CORE-035`, `AEG-LOG-042`),
  and Aegis must not depend on Praxis at runtime or build time.

## Decision

1. **Carry, do not redefine.** Aegis embeds the Praxis block verbatim. It adds
   no actor type of its own beyond a plain mirror of the Praxis actor fields,
   and it keeps `RecoveryActor` as a role category.
2. **Provenance travels beside the event, not inside the published records.**
   A new `AttributedEvent = { Event; Provenance }` pairs an unchanged
   `AegisEvent` with an optional `ProvenanceBlock`. Serialization writes the
   block under the event's `provenance` field; events without one are
   byte-for-byte what they were. `Fault`, `AegisEvent`, `RecoveryAttempt`,
   `Resolution`, `AegisConfig`, `Store.Indexed` and `Tutela.Evidence` are
   unchanged. The schema literals stay `aegis/event/v1` and `aegis/fault/v1`
   because the field is optional and readers already tolerate unknown fields
   (`AEG-LOG-012`).
3. **A block cannot be malformed once it exists.** `ProvenanceBlock` is only
   constructed by classifying JSON (supported or unsupported) or by the
   codec's own append, so malformed provenance is rejected when it is built or
   appended and can never reach a sink.
4. **Later contributors live on later events.** The recording event carries
   `created` + `discovered`; recovery attempts carry `remediated`; verified
   resolution carries `validated`; acknowledgement `reviewed`; escalation and
   reopening `modified`; supersession `superseded`. A pure projection folds a
   fault's attributed event stream into its accumulated block with Praxis's
   append rules, reporting refused contributions as conflicts and carrying
   unsupported-major blocks verbatim beside it.
5. **Lineage and evidence by reference.** Affected artifacts go in
   `derivedFrom` (`git:commit/<sha>` from `EnvironmentInfo.CommitSha`, plus
   caller-supplied references). Environment, snapshot and breadcrumb material
   is referenced from the discovering contribution's `evidence`
   (`aegis:fault/<id>#environment`, `aegis:snapshot/<digest>`,
   `aegis:fault/<id>#breadcrumbs`), never copied.
6. **Tutela gets `contributionProvenance`.** An additive
   `Tutela.AttributedEvidence` carries the accumulated block under
   `contributionProvenance`. Tutela's `provenance` already means issuer/run
   attestation and `producerIdentity` means an attested producer; self-reported
   contribution identity is neither.
7. **Conformance through vendored fixtures.** `cases.json` and
   `echelon-chain.json` (and, from contract revision 1.1,
   `identity-environment.json`) are vendored unchanged from Praxis commit
   `c2657efb4d54f11d0fd0617cc1bcd5b8418601d5` with their SHA-256 in
   `tests/fixtures/praxis-provenance/SOURCE.json`; a small F# codec in
   `Aegis.Core` (`Provenance.fs`, System.Text.Json only) is tested against
   every case.

8. **Redaction rules reject, they do not rewrite (revision 1.1).**
   Provenance is carried verbatim, so the application's `Redaction.Rule`s are
   applied to a block's field names and free-text values (reason, evidence,
   lineage, actor id/provider/model/runtime, unknown fields) and a match
   rejects the block: `Provenance.attachWith` and `Aegis.reportAttributed`
   return an error, `Aegis.captureAttributed` records the fault unattributed
   and reports the refusal to the fallback, and the serializer writes
   `provenanceRejected` instead of the block as a last line of defence. The
   fault form is now built structurally rather than by string replacement,
   which could rewrite text inside a carried block.

## Alternatives rejected

- **Add `Provenance: ... option` to `Fault`, `RecoveryAttempt`, `Resolution`.**
  Breaks every consumer constructing those records (the C# consumability
  tests and Praxis among them) without a major version bump.
- **New `AegisEvent` cases (e.g. `ContributionRecorded`).** Breaks exhaustive
  matches in consumers that treat warnings as errors, and splits one lifecycle
  fact across two events.
- **Turn `RecoveryActor` into an identity.** It answers "what kind of party
  initiated recovery", a question the Praxis actor does not replace; merging
  them would conflate role with identity.
- **Reuse Tutela's `provenance` or `producerIdentity`.** Both have attested
  meanings in Tutela; self-reported identity must not masquerade as either.
- **Depend on a Praxis package.** Violates Echelon's independence invariant.

## Consequences

- Faults and every lifecycle event can be attributed; old events read as
  unattributed and stay valid.
- Consumers opt in through `Aegis.reportAttributed`, `Aegis.captureAttributed`,
  `Serialization.attributedEvent`, `Store.provenanceOf` and
  `ProvenanceHistory`; nothing existing changes behaviour.
- **Limitation:** identity is self-reported provenance, not authentication.
- **Limitation:** the credential tripwire recognises common token shapes only.
- **Limitation:** Aegis still lacks Tutela `producerIdentity`,
  `artifactDigest` and attested `provenance`; this decision does not add them.
- **Limitation:** `Lifecycle.Projected` does not carry provenance; use
  `ProvenanceHistory` beside it rather than widening a published record.

- **Limitation:** Aegis's default `credentials` rule matches the name
  `signature`, so a future Praxis attestation field named `signature` is
  refused under the default rules. An application that wants to carry
  attestations must use rules that do not match it; revisit when Praxis
  defines attestation fields.

## Revisit when

- A shared .NET provenance codec package is published (replace `Provenance.fs`).
- A `praxis.provenance/2` major is introduced.
- Aegis takes a major version bump, at which point provenance may move onto the
  records themselves.
