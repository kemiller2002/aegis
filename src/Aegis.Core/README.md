# Aegis.Core

Aegis handles **unexpected operational failure**: the GitHub call that times
out, the stored file that will not parse, the interop bridge that disappears.
It exists so that handling those failures does not mean threading an error
type through every method signature, and so that swallowing them is not an
option.

`Aegis.Core` has **no third-party dependency at all** — no logging framework,
no DI container, no telemetry or storage SDK. Everything it needs to run is
in this one package.

## Install

```
dotnet add package EchelonFoundry.Aegis.Core
```

## Use it at a boundary

```fsharp
// Loading time entries crosses into GitHub. That is a boundary.
let scope = Aegis.scope config "Chrona.TimeEntry.Load" (Map [ "repository", Public repo ])

match Aegis.capture config scope classifyGitHubFailure (fun () -> repository.load entryId) with
| Ok entries -> render entries
| Result.Error fault -> presentFault (Presentation.present "Unable to load time entries" fault)
```

`capture`, `report`, `guard` and `suppress` (and their async pairs) are the
core of the API. A fault is a single structured type: severity, failure domain,
blast radius, retention, redacted context, and a causal chain back to what
actually broke. Recovery is proposed as data — Aegis never applies a
transition itself — and presentation is intent, not markup, so the same
fault can drive a UI, a CLI, or an agent without either side knowing about
the other.

## Failures are explicit, including persistence failures

- A **timeout is a fault, not a cancellation** — HttpClient's own timeout
  (`TaskCanceledException` wrapping `TimeoutException`) is recorded by
  `capture` and `guard`. `Aegis.withTimeouts` gives it the stable code
  `AEGIS.NETWORK.TIMEOUT`.
- **`captureReported`** returns the fault together with its `Delivery`:
  `Persisted`, `RequiredSinkFailed` or `NotAwaited`. Use it when a Required
  sink must hold the record.
- **`guardOutcome`** names every exit of the final boundary:
  `Termination.Completed | Cancelled | Faulted`.
- **Short-lived processes:** `Aegis.forCommandLine config` awaits delivery
  and writes sink failures to stderr; or call `Aegis.flush timeout` before
  exit. The default stays `Detached` for long-running hosts.
- `Catalog.builtIn` covers every `AEGIS.*` code the library raises.

See [Explicit failure semantics](https://github.com/kemiller2002/aegis/blob/main/docs/aegis/README.md#explicit-failure-semantics)
for the 1.0.0 → 1.1.0 compatibility table.

## Test it by replacing the sinks

```fsharp
let collector = Sinks.Collector()
Aegis.capture { config with Sinks = [ collector.Sink ] } scope classify operation
Assert.Single(collector.Events)
```

No sink writes anywhere by default in a test; assert on what was collected,
never on console output.

## What this package is not

Aegis produces structured diagnostic events. It is not a logging framework,
a metrics platform, a tracing product, an analytics system or a monitoring
tool. Storage lives in adapters you opt into —
[`EchelonFoundry.Aegis.Store.GitHub`](https://www.nuget.org/packages/EchelonFoundry.Aegis.Store.GitHub)
is the reference one, built against the `Store.T` contract this package
declares.

## Documentation

- [Using Aegis](https://github.com/kemiller2002/aegis/blob/main/docs/aegis/README.md) — the full guide: when to use it, when not to, translation, recovery, testing.
- [Agent integration](https://github.com/kemiller2002/aegis/blob/main/docs/aegis/AGENT-INTEGRATION.md) — for an AI agent adding Aegis to a codebase.
- [Requirement traceability](https://github.com/kemiller2002/aegis/blob/main/docs/aegis/REQUIREMENTS-STATUS.md) — what is implemented and tested, and what is not.

Source: [github.com/kemiller2002/aegis](https://github.com/kemiller2002/aegis) · License: MIT
