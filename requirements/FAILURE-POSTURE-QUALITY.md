# Aegis Failure-Posture Quality Requirements

Status: proposed requirements
Date: 2026-10-04

Aegis should make unexpected boundary failure explicit enough that application code cannot accidentally turn corruption or dependency failure into a healthy default.

## AEGIS-QUAL-001 - Typed failure posture
Priority: critical

Define a reusable failure-posture vocabulary for boundary operations: FailClosed, FailOpen, and Indeterminate/Reconcile. The posture is metadata about handling authority, not a replacement for domain outcomes.

## AEGIS-QUAL-002 - Corrupt required state is a fault
Priority: critical

Provide a standard classification for malformed, truncated, incompatible, or unreadable required persistent state. Boundary helpers SHALL preserve the original failure and SHALL NOT silently return empty/default state.

## AEGIS-QUAL-003 - External adapter fault normalization
Priority: high

Normalize unexpected filesystem, process, network, credential-store, protocol, timeout, and persistence exceptions into stable Aegis fault codes at Infrastructure boundaries. Expected provider/domain outcomes remain typed application/domain results.

## AEGIS-QUAL-004 - No-swallow critical-boundary rule
Priority: high

Add analyzable/testable guidance and helpers that discourage catch-all exception swallowing at required-state and authorization/gating boundaries. A best-effort diagnostic/log path may swallow only after the authoritative outcome is already preserved.

## AEGIS-QUAL-005 - Recovery posture and observability
Priority: high

Faults SHALL be able to state whether retry, operator intervention, reconciliation, fallback, or explicit override is permitted. Telemetry SHALL preserve code, boundary, recovery posture, and redacted cause without leaking credentials.

## AEGIS-QUAL-006 - Persistence boundary integration examples
Priority: medium

Add reference implementations/tests showing how an application such as Praxis handles corrupt versioned state: Infrastructure returns a typed Aegis fault; Application chooses fail-closed or indeterminate behavior; CLI renders it without converting it to success.

## Boundary principle

Aegis does not decide whether a business/domain condition is legal. It guarantees that unexpected operational failure remains visible and typed until the owning domain/application deliberately decides what to do.
