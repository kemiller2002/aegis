---
id: GV-AEGIS-001
title: Using Aegis
status: draft
version: 1.2.0
owners:
  - repository-governance
created: 2026-09-17
updated: 2026-10-05
related_documents:
  - docs/aegis/REQUIREMENTS-STATUS.md
  - docs/aegis/AGENT-INTEGRATION.md
  - docs/aegis/PUBLISHING.md
  - Input-documents/aegis_initial_requirements.txt
  - research/decisions/DF-AEGIS-2026-0CA3--aegis-implementation-sequencing.md
  - aegis-boundaries.json
tags: [aegis, documentation, faults]
---

# Using Aegis

Aegis handles **unexpected operational failure**: the GitHub call that times out,
the stored file that will not parse, the interop bridge that disappears. It
exists so that handling those failures does not mean threading an error type
through every method signature, and so that swallowing them is not an option.

## Install

```
dotnet add package EchelonFoundry.Aegis.Core
```

Add `EchelonFoundry.Aegis.Store.GitHub` if you store events in GitHub, and
`EchelonFoundry.Aegis.Integration.GitHub` if you also call the GitHub API
directly. An AI agent adding Aegis to a codebase should read
[`AGENT-INTEGRATION.md`](AGENT-INTEGRATION.md) instead of this document —
it is a mechanical runbook rather than a design explanation. How these
packages are built and released is in [`PUBLISHING.md`](PUBLISHING.md).

Every example below is a real scenario from this repository or from Chrona.
There is no `FooException` anywhere in this document, deliberately.

Where each requirement is implemented and tested, and what is not done yet, is
in [`REQUIREMENTS-STATUS.md`](REQUIREMENTS-STATUS.md).

## When to use Aegis

Use Aegis at an architectural boundary, where something outside your code can
fail in a way your domain model does not describe:

```fsharp
// Loading time entries crosses into GitHub. That is a boundary.
let scope = Aegis.scope config "Chrona.TimeEntry.Load" (Map [ "repository", Public repo ])

match Aegis.capture config scope classifyGitHubFailure (fun () -> repository.load entryId) with
| Ok entries -> render entries
| Result.Error fault -> presentFault (Presentation.present "Unable to load time entries" fault)
```

The boundaries this repository recognises are declared in
[`aegis-boundaries.json`](../../aegis-boundaries.json), and tests check that
declaration against the code.

## When **not** to use Aegis

Do not use Aegis for outcomes your domain already models. These are not faults;
they are answers:

```fsharp
// Right: the domain says so, in the type.
type ApprovalOutcome =
    | Approved of TimeEntry
    | AlreadyApproved
    | MissingRequiredEvidence

// Wrong: this is not an operational failure, and Aegis would obscure it.
Aegis.capture config scope classify (fun () ->
    if entry.Approved then failwith "already approved" else approve entry)
```

`InvoiceAlreadyPaid`, `TimeEntryAlreadyApproved` and `IllegalStateTransition`
belong in discriminated unions, `Result`, or SDE transitions. Aegis is for the
GitHub outage, not the business rule.

Do not scatter `try ... with` through domain code either. If you find yourself
wanting one, you are probably at a boundary that should be declared.

## What is never acceptable

```fsharp
// Both of these are invalid in this codebase.
try doSomething () with _ -> ()
try Some (load ()) with _ -> None
```

An intercepted unexpected failure must end in one of four places:
propagation, recovery, a state transition, or suppression **under a declared
policy**. Suppression is recorded as a `FaultSuppressed` event, so even a
deliberate silence is visible:

```fsharp
Aegis.suppress config fault "offline mode: retry queued"
```

`Aegis.capture` returns `Result<'T, Fault>`, so a caller cannot ignore a
failure by accident. Because capture belongs at boundaries, this does not
spread `Result` through unrelated code.

## Creating a typed fault

An integration assembly owns its own failure model. It knows *what* failed;
Aegis knows *how* the fault is represented:

```fsharp
type T =
    | AuthenticationFailed
    | RepositoryNotFound of repository: string
    | RateLimited of retryAfter: TimeSpan option
    | NetworkUnavailable
    | InvalidResponse of detail: string

let mapping: Translation.Mapping<T> =
    { Code = code
      Category = category
      Severity = severity
      Impact = impact
      Persistence = persistence
      Recovery = recovery
      UserMessage = userMessage
      Owner = "GitHubIntegration"
      Dependencies = [ "GitHubIntegration"; "GitHubApi" ] }
```

Fault codes are stable (`AEGIS.GITHUB.RATE_LIMITED`); user-facing messages are
not. Tooling, tests, agents and recovery rules key off the code.

## Translating infrastructure exceptions

`HttpRequestException` must not escape the GitHub boundary, and a malformed
body is not a connectivity problem:

```fsharp
let ofException (ex: exn) =
    match ex with
    | :? TimeoutException -> Timeout
    | :? Net.Http.HttpRequestException -> NetworkUnavailable
    | :? Text.Json.JsonException as json -> InvalidResponse $"malformed response: {json.Message}"
    | other -> InvalidResponse other.Message
```

Translation never discards the original: the exception type, message, stack
trace and inner exception are preserved as the fault's `Cause`, kept apart
from anything a user sees.

## Explicit failure semantics

Since 2.0.0 these rules are enforced by code and tests, not convention
(aegis#13, AEGIS-QUAL-002..006):

- **A timeout is a failure, not a cancellation.** `Aegis.isCancellation` is
  true only for a cancellation nobody can mistake for a timeout.
  HttpClient reports its own `Timeout` as a `TaskCanceledException` wrapping
  a `TimeoutException`; `Aegis.isTimeout` recognises it, `capture` records
  it as a fault, and `guard` no longer drops it. `Aegis.withTimeouts`
  composes over a classifier to give every timeout the stable
  `AEGIS.NETWORK.TIMEOUT` infrastructure code.
- **A persistence failure is visible to the caller.** `captureReported` /
  `captureReportedAsync` return the fault *and* a `Delivery`:
  `Persisted`, `RequiredSinkFailed` (a Required sink did not write the
  record) or `NotAwaited` (Detached mode: the outcome is unknown). Use them
  wherever a Required sink must hold the record. `capture` keeps its
  original shape for compatibility and does not carry the delivery.
- **The final boundary names every exit.** `guardOutcome` /
  `guardOutcomeAsync` return `Termination.Completed`, `Termination.Cancelled`
  (the caller's own cancellation only) or `Termination.Faulted` with the
  delivery outcome. `guard` returns the same decision as `unit`.
- **Short-lived processes do not lose detached faults silently.** The
  default persistence mode stays `Detached` (unchanged for long-running
  hosts). A command-line tool either opts into
  `Aegis.forCommandLine config` (Blocking delivery, sink failures written to
  standard error), or calls `Aegis.flush timeout` before exit;
  `FlushOutcome.TimedOut` says deliveries may be lost, and
  `Aegis.detachedStatus ()` counts detached deliveries whose Required sink
  failed.
- **Partial failure is not success.** A store query that cannot read every
  record answers `Store.Malformed`, naming each unreadable record
  (`Store.complete`). `GitHubStore.queryDetailed` returns the readable
  records *and* the unreadable list, for a caller that wants both.
- **Replay is idempotent.** The GitHub sink stores and queues each event
  under the event id inside its payload, and an append that finds the
  identical record already stored succeeds without writing. A batch that
  half-committed completes on replay instead of conflicting with itself; a
  *different* record at the same path is still a `Conflict`.
- **Retry exhaustion is terminal and recorded.** `Recovery.attempt` returns
  `Refused (AttemptsExhausted n, [RecoveryConcluded ...])`, and likewise for
  `UnsafeToRepeat`; `Recovery.isTerminal` identifies both.
- **Every Aegis fault code is catalogued.** `Catalog.builtIn` holds an entry
  for every `FaultCode "AEGIS.*"` in the source; a test fails if a new code
  is added without one.

### Compatibility for consumers upgrading from 1.0.0

**2.0.0 is a major release.** No public signature was removed or changed,
and the new union types require qualified access (`Delivery.Persisted`,
`Termination.Completed`, `FlushOutcome.Flushed`) so they cannot shadow a
consumer's own case names — so a consumer still compiles. But the
behaviour is not compatible: a `GitHubStore` query that used to succeed,
returning `Ok` with unreadable records silently skipped, now fails closed
with `Error (Store.Malformed ...)`. A call that succeeded on 1.0.0 can fail
on 2.0.0, so the version is a major one rather than 1.1.0. Every other
change below turns a silent outcome into an explicit one:

| Before (1.0.0) | After (2.0.0) |
|---|---|
| `GitHubStore` query returned `Ok` and skipped unreadable records. | **Breaking:** it returns `Error (Store.Malformed ...)` naming them; use `queryDetailed` for the readable part. |
| An HttpClient timeout escaped `capture` as `TaskCanceledException`, and `guard` dropped it. | It reaches `classify`, is recorded, and is returned as a fault. |
| `GitHubFailure.ofException` mapped an HttpClient timeout to `InvalidResponse`. | It maps to `Timeout` (`AEGIS.NETWORK.TIMEOUT`, retryable). |
| The GitHub sink filed events under a freshly minted id. | It files them under the payload's own event id. |
| Re-appending an identical stored record was a `Conflict`. | It succeeds without writing. |
| An exhausted or unsafe-to-repeat recovery carried no event. | It carries one `RecoveryConcluded (..., FailedWith ...)` event. |

#### Migrating store queries

A consumer that relied on the 1.0.0 behaviour — take whatever records can be
read and carry on — calls `GitHubStore.queryDetailed` instead of the store's
`Query`. It returns the readable records *and* the unreadable list together,
so the partial answer is still available but no longer silent:

```fsharp
match! GitHubStore.queryDetailed config operations query with
| Error storeError -> handle storeError                 // e.g. Store.Unavailable
| Ok outcome ->
    consume outcome.Matched                             // the readable records
    for unreadable in outcome.Unreadable do              // { Path; Reason }
        reportUnreadable unreadable.Path unreadable.Reason
```

`Store.complete outcome` collapses the same outcome back to the fail-closed
answer (`Ok` only when every record was read). A consumer that only wants
complete answers needs no change beyond handling `Store.Malformed`.

Praxis and other consumers pinned to 1.0.0 are unaffected until they move
the pin. A CLI that upgrades should adopt `forCommandLine` or `flush` and,
where it renders a fault reference, prefer `captureReported` so it does not
print a reference for a record that was never persisted.

## How recovery works

Aegis proposes; it does not decide. Authorization is injected, and the default
authority permits nothing:

```fsharp
let authority = { Recovery.Authorize = fun fault action -> sdeDecides fault action }

match Recovery.attempt authority Agent now 1 idempotent perform verify fault with
| Recovery.Attempt attempted -> record attempted.Events
| Recovery.Refused (reason, events) ->
    // A terminal refusal (Recovery.isTerminal: retries exhausted, or unsafe
    // to repeat) carries a RecoveryConcluded event. Record it: retry
    // exhaustion must never end silently.
    record events
    explain reason
```

Three rules that are easy to get wrong:

- **Retry only where repeating is safe.** A failed read may be retried; a
  partially completed write may not. Pass `idempotent` honestly.
- **Recovery is not successful because it returned.** Supply `verify`; a
  recovery that runs but leaves the condition is a failure.
- **Manual intervention is never automatic.** It raises an obligation that
  stays visible until discharged.

## How SDE interacts with faults

A fault may *propose* a transition. SDE decides whether it is legal:

```fsharp
match Sde.forFault fault with
| Some proposal -> sde.Request proposal   // e.g. AuthenticationRequired
| None -> ()
```

Aegis never applies a transition and never bypasses a rule. Safe modes
(`ReadOnly`, `Offline`, …) go through the same door.

## How Limen presents faults

Aegis produces intent and structure, never markup:

```fsharp
let presented = Presentation.present "Unable to load time entries" fault
// presented.Intent      -> Notification
// presented.Message     -> "GitHub could not be reached."
// presented.Actions     -> [ { Label = "Try again"; Capability = CanRetry } ]
// presented.Reference   -> "AG-ABCDE"
```

Limen renders it. Repeated faults are throttled by fingerprint, so fifty
network failures produce fifty diagnostic occurrences and one notification.

Limen is a reference consumer, not a dependency. Nothing in this repository
imports it, and `Presentation.present` is tested against the intent it
returns, not against a renderer. `aegis-boundaries.json` declares the
`Limen interop` boundary with `guarded: false` for exactly that reason: the
far side of the boundary is not here, and a declaration that says so is worth
more than a check that cannot fail. See
[`DF-AEGIS-2026-DBBD`](../../research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md).

## How to test fault behaviour

Replace the sinks and assert on what was collected. Never inspect console
output:

```fsharp
let collector = Sinks.Collector()
let config = { config with Sinks = [ collector.Sink() ] }

Aegis.capture config scope classify (fun () -> failwith "GitHub unreachable") |> ignore

Assert.Contains("CHRONA.GITHUB.LOAD_FAILED", collector.Codes)
```

Inject the clock and randomness so tests are deterministic:

```fsharp
{ config with
    Now = fun () -> DateTimeOffset(2026, 9, 17, 12, 0, 0, TimeSpan.Zero)
    Random = fun () -> 1L, 2L }
```

Every integration assembly needs contract tests proving its translation: 401
becomes `AuthenticationFailed`, 429 becomes `RateLimited`, a malformed body
becomes `InvalidResponse`, and no raw technology exception crosses the
boundary.

## What Aegis is not

Aegis produces structured diagnostic events. Telemetry systems consume them.
Aegis is not a logging framework, a metrics platform, a tracing product, an
analytics system or a monitoring tool, and its core takes no third-party
dependency at all. Storage lives in adapters you opt into.

This repository ships one of them. `Aegis.Store.GitHub` is the reference
adapter -- it takes injected operations rather than a client library, so it
keeps `Store.T` honest without bringing a dependency into the solution.
Database adapters (Postgres, SQL Server, SQLite) are written against the same
contract *outside* this repository, where the driver belongs; that is a
packaging decision, recorded in
[`DF-AEGIS-2026-DBBD`](../../research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md),
and it is what keeps the core dependency-free by construction rather than by
discipline.
