---
id: GV-AEGIS-001
title: Using Aegis
status: draft
version: 1.1.0
owners:
  - repository-governance
created: 2026-09-17
updated: 2026-09-17
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

## How recovery works

Aegis proposes; it does not decide. Authorization is injected, and the default
authority permits nothing:

```fsharp
let authority = { Recovery.Authorize = fun fault action -> sdeDecides fault action }

match Recovery.attempt authority Agent now 1 idempotent perform verify fault with
| Recovery.Attempt attempted -> record attempted.Events
| Recovery.Refused (reason, _) -> explain reason
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
