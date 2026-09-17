---
id: GV-AEGIS-004
title: Agent integration guide
status: draft
version: 1.0.0
owners:
  - repository-governance
created: 2026-09-17
related_documents:
  - docs/aegis/README.md
  - docs/aegis/REQUIREMENTS-STATUS.md
  - docs/aegis/PUBLISHING.md
tags: [aegis, documentation, agents]
---

# Agent integration guide

This is a mechanical runbook for an AI coding agent adding
[`EchelonFoundry.Aegis.Core`](https://www.nuget.org/packages/EchelonFoundry.Aegis.Core)
to a .NET codebase. It assumes the reader is following instructions, not
learning the design — for the why, read
[`docs/aegis/README.md`](README.md) first if there is time to.

## 1. Install

```
dotnet add package EchelonFoundry.Aegis.Core
```

Add `EchelonFoundry.Aegis.Store.GitHub` only if the host application stores
its events in GitHub, and `EchelonFoundry.Aegis.Integration.GitHub` only if
the host application also calls the GitHub API directly and wants its
failures translated. Most consumers need `Aegis.Core` alone.

## 2. Configure once, at startup

```fsharp
open Aegis

let config =
    Aegis.configure "MyApp" (Some "1.0.0") [ Sinks.console ]
```

`configure` takes an application name, an optional version, and a list of
sinks. Add more sinks (`Sinks.file "path.jsonl"`, a `Sinks.Collector` for
tests, or a custom `Aegis.Core.Sinks.Sink` record) by extending that list —
do not build `AegisConfig` by hand unless there is a specific reason to
override a field `configure` sets by default (`Persistence = Detached`,
`Now = DateTimeOffset.UtcNow`, redaction rules from `Redaction.defaultRules`).

Validate the configuration before trusting it:

```fsharp
match Bootstrap.validate None config with
| Ok _ -> ()
| Result.Error problems -> problems |> List.iter (fun p -> printfn "%A" (Bootstrap.describe p))
```

Configuration is supplied once and passed explicitly; there is no ambient
singleton to reach for.

## 3. Find the boundaries, not the exceptions

Aegis goes at **architectural boundaries** — the edge where something
outside the process can fail in a way the domain model does not already
describe: an HTTP call, a file read, a database query, an interop bridge.

It does **not** go around code that already has a typed outcome (a
discriminated union your own domain defines) or around a programming defect
(`NullReferenceException`, `ArgumentException`, `IndexOutOfRangeException`,
`InvalidOperationException` — these are deliberately re-raised, never
captured, because core 19 requires defects to fail loudly). Do not wrap a
`try/with` around business logic to "be safe" — that is exactly the
`Result<Result<...>>` smell Aegis exists to prevent.

If you are integrating an agent's own generated code and are unsure whether
a given call site is a boundary: it is one if the failure can come from
outside this process (network, disk, another service), and it is not one if
the failure is a business rule your own types can express instead.

## 4. Wrap the boundary with `capture`

```fsharp
let scope = Aegis.scope config "MyApp.LoadWidget" (Map [ "widgetId", Public widgetId ])

let classify (scope: Scope) (ex: exn) =
    Aegis.faultOf
        config scope
        (FaultCode "MYAPP.WIDGET.LOAD_FAILED")
        IntegrationFailure
        FaultSeverity.Error
        FeatureUnavailable
        RequiresIntervention
        ManualIntervention
        "Unable to load the widget."
        ex

match Aegis.capture config scope classify (fun () -> repository.Load widgetId) with
| Ok widget -> render widget
| Result.Error fault -> presentFault (Presentation.present "Unable to load the widget" fault)
```

For an `async` operation use `captureAsync` in place of `capture` — same
signature, `operation: unit -> Async<'T>`, returns `Async<Guarded<'T>>`.

For the top-level entry point of a process (a command loop, a startup
routine, a UI event dispatcher) use `guard` / `guardAsync` instead: they are
the last line of defence, always report what they catch (blocking, so a
detached write is not lost as the process exits), still re-raise a
programming defect after recording it, and swallow cancellation without
recording it.

`classify` is the one piece every call site supplies itself: what fault code,
category, severity and recovery policy this particular failure deserves.
`Aegis.faultOf` builds the `Fault` record from that plus the exception; there
is no default classifier because guessing severity from an exception type
would be exactly the kind of silent, undifferentiated handling Aegis exists
to replace.

## 5. Translating an integration's own failure type

If the host application (or another package) already has its own typed
failure model — the way `GitHubFailure.T` does for GitHub — do not reclassify
each raw exception at every call site. Declare one `Translation.Mapping`
for that type instead:

```fsharp
let mapping: Translation.Mapping<MyIntegrationFailure> =
    { Code = fun f -> FaultCode $"MYAPP.INTEGRATION.{f}"
      Category = fun _ -> IntegrationFailure
      Severity = fun _ -> FaultSeverity.Error
      Impact = fun _ -> FeatureUnavailable
      Persistence = fun _ -> RequiresIntervention
      Recovery = fun _ -> ManualIntervention
      UserMessage = fun _ -> "The integration is unavailable."
      Owner = "MyIntegration"
      Dependencies = [ "MyApp"; "MyIntegration" ]
      Domain = fun _ -> IntegrationDomain
      Radius = fun _ -> OneOperation
      Retention = fun _ -> DiagnosticOnly }
```

`Translation.toFault mapping identity (application, version) operation
context cause failure` turns one value of `MyIntegrationFailure` into a
`Fault` using that mapping. Write this once per integration assembly, not
once per call site.

## 6. Test it by replacing the sinks — never by reading output

```fsharp
let collector = Sinks.Collector()
let testConfig = Aegis.configure "MyApp" None [ collector.Sink() ]

match Aegis.capture testConfig scope classify failingOperation with
| Result.Error _ -> ()
| Ok _ -> failwith "expected a fault"

Assert.Single(collector.Events)
Assert.Contains("MYAPP.WIDGET.LOAD_FAILED", collector.Codes)
```

Never assert on console output or a real file. `Sinks.Collector` exists
specifically so tests are deterministic and do not touch the filesystem or
network — see core 27 (deterministic testability with replaceable sinks).

## 7. Checklist before opening a PR that adds Aegis

- [ ] Every new boundary uses `capture`/`captureAsync` (or `guard`/`guardAsync`
      for a true top-level entry point) — not a bare `try/with`.
- [ ] No domain-modeled outcome (something your own DU already expresses) was
      routed through Aegis instead.
- [ ] `classify` supplies a real `FaultCode`, not a placeholder string.
- [ ] Tests use `Sinks.Collector`, not real sinks or console assertions.
- [ ] If this PR introduces a new integration assembly, it declares one
      `Translation.Mapping` rather than classifying at every call site.
- [ ] Nothing sensitive (tokens, PII) reaches `Context` unredacted — check
      against [`Redaction.defaultRules`](README.md#redaction) or add a rule.

## Further reading

- [`docs/aegis/README.md`](README.md) — the full guide, including recovery,
  escalation, presentation intent, and what Aegis deliberately is not.
- [`docs/aegis/REQUIREMENTS-STATUS.md`](REQUIREMENTS-STATUS.md) — what is
  implemented and tested, item by item.
- [`docs/aegis/PUBLISHING.md`](PUBLISHING.md) — how these packages are built
  and released, if you are working on Aegis itself rather than consuming it.
