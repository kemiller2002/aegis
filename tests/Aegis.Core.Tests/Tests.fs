module Aegis.Tests.Core

open System
open Xunit
open Aegis

/// Deterministic configuration: fixed clock and fixed randomness, so no test
/// depends on wall-clock time or console output. Requirement: core 27.
let private at = DateTimeOffset(2026, 9, 17, 12, 0, 0, TimeSpan.Zero)

let private configWith sinks =
    { Application = "Chrona"
      Version = Some "1.4.2"
      Sinks = sinks
      Rules = Redaction.defaultRules
      Fallback = ignore
      Now = fun () -> at
      Random =
        let counter = ref 0L
        fun () ->
            let n = System.Threading.Interlocked.Increment counter
            n, n * 7L }

let private classify (scope: Scope) (ex: exn) =
    Aegis.faultOf
        (configWith [])
        scope
        (FaultCode "CHRONA.GITHUB.LOAD_FAILED")
        IntegrationFailure
        FaultSeverity.Error
        OperationOnly
        Transient
        (Retry(3, Exponential(TimeSpan.FromSeconds 1.)))
        "Unable to load time entries."
        ex

// ---------------------------------------------------------------- identifiers

[<Fact>]
let ``identifiers are sortable by time`` () =
    let earlier = Id.generate at (1L, 1L)
    let later = Id.generate (at.AddMilliseconds 1.) (1L, 1L)
    Assert.True(earlier < later, $"{earlier} should sort before {later}")

[<Fact>]
let ``event id is distinct from fault id`` () =
    // Requirement: logging 24.
    let config = configWith []
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    let fault = classify scope (Exception "boom")
    let collector = Sinks.Collector()
    let config = { config with Sinks = [ collector.Sink() ] }
    Aegis.report config (FaultRecorded fault) |> ignore
    let payload = List.head collector.Events
    Assert.Contains($"\"faultId\":\"{fault.Id.Value}\"", payload)
    Assert.DoesNotContain($"\"eventId\":\"{fault.Id.Value}\"", payload)

// ------------------------------------------------------------------ redaction

[<Theory>]
[<InlineData("github_token")>]
[<InlineData("Authorization")>]
[<InlineData("api_key")>]
[<InlineData("session-id")>]
[<InlineData("user.password")>]
[<InlineData("privateKey")>]
[<InlineData("cookie")>]
let ``credential keys are dropped whatever their classification`` key =
    // Requirements: core 12, logging 21. A mislabelled credential is still a credential.
    let context = Map [ key, Public "ghp_secretvalue" ]
    let redacted = Redaction.apply Redaction.defaultRules context
    Assert.Equal(Redaction.Placeholder, redacted.[key])

[<Fact>]
let ``secret classification is never persisted`` () =
    // Requirement: additional 27.
    let context = Map [ "harmlessName", Secret "value" ]
    Assert.Equal(Redaction.Placeholder, (Redaction.apply Redaction.defaultRules context).["harmlessName"])

[<Fact>]
let ``sensitive is masked and public is kept`` () =
    let context = Map [ "email", Sensitive "a@b.c"; "repository", Public "aegis" ]
    let redacted = Redaction.apply Redaction.defaultRules context
    Assert.Equal(Redaction.Placeholder, redacted.["email"])
    Assert.Equal("aegis", redacted.["repository"])

[<Fact>]
let ``applications can register additional rules without losing defaults`` () =
    // Requirement: core 12.
    let rules =
        Redaction.defaultRules
        |> Redaction.withRule
            { Name = "employee-id"
              AppliesTo = fun k -> k.Contains "employeeId" }

    let context = Map [ "employeeId", Public "E-1"; "token", Public "t"; "repo", Public "aegis" ]
    let redacted = Redaction.apply rules context
    Assert.Equal(Redaction.Placeholder, redacted.["employeeId"])
    Assert.Equal(Redaction.Placeholder, redacted.["token"])
    Assert.Equal("aegis", redacted.["repo"])

[<Fact>]
let ``redaction is observable rather than silent`` () =
    // Requirement: core 7 applied to redaction.
    let context = Map [ "token", Public "t"; "email", Sensitive "a@b.c"; "repo", Public "aegis" ]
    let audit = Redaction.audit Redaction.defaultRules context |> Map.ofList
    Assert.Equal("rule:credentials", audit.["token"])
    Assert.Equal("classification:sensitive", audit.["email"])
    Assert.False(audit.ContainsKey "repo")

[<Fact>]
let ``no sink ever receives an unredacted secret`` () =
    // Requirement: logging 21 -- redaction happens before any sink is reached.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" (Map [ "github_token", Public "ghp_leaked" ])
    let fault = classify scope (Exception "boom")
    Aegis.report config (FaultRecorded fault) |> ignore
    Assert.DoesNotContain("ghp_leaked", List.head collector.Events)

// -------------------------------------------------------------- serialization

[<Fact>]
let ``serialized events carry the schema version`` () =
    // Requirements: core 37, logging 12.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Aegis.report config (FaultRecorded(classify scope (Exception "boom"))) |> ignore
    Assert.Contains($"\"schema\":\"{Schema.Event}\"", List.head collector.Events)

[<Fact>]
let ``timestamps are serialized as UTC`` () =
    // Requirement: logging 25.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Aegis.report config (FaultRecorded(classify scope (Exception "boom"))) |> ignore
    Assert.Contains("\"timestamp\":\"2026-09-17T12:00:00.000Z\"", List.head collector.Events)

[<Fact>]
let ``causal chain is preserved rather than flattened`` () =
    // Requirements: core 15, 17.
    let inner = Exception "HTTP timeout"
    let outer = Exception("GitHub file load failed", inner)
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Aegis.report config (FaultRecorded(classify scope outer)) |> ignore
    let payload = List.head collector.Events
    Assert.Contains("GitHub file load failed", payload)
    Assert.Contains("HTTP timeout", payload)
    Assert.Contains("\"inner\"", payload)

// ------------------------------------------------------------------- capture

[<Fact>]
let ``capture returns the value on success and records nothing`` () =
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    let result = Aegis.capture config scope classify (fun () -> 42)
    Assert.Equal(Ok 42, result)
    Assert.Empty collector.Events

[<Fact>]
let ``capture surfaces the fault in the type rather than swallowing it`` () =
    // Requirement: core 7.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    let result = Aegis.capture config scope classify (fun () -> failwith "GitHub unreachable")
    match result with
    | Ok _ -> failwith "expected a fault"
    | Result.Error fault -> Assert.Equal("CHRONA.GITHUB.LOAD_FAILED", fault.Code.Value)
    Assert.Single collector.Events |> ignore

[<Fact>]
let ``programming defects are not converted into faults`` () =
    // Requirement: core 19 -- they must fail loudly.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Assert.Throws<InvalidOperationException>(fun () ->
        Aegis.capture config scope classify (fun () -> raise (InvalidOperationException "impossible case"))
        |> ignore)
    |> ignore
    Assert.Empty collector.Events

[<Fact>]
let ``cancellation is not reported as a fault`` () =
    // Requirement: core 29.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Assert.Throws<OperationCanceledException>(fun () ->
        Aegis.capture config scope classify (fun () -> raise (OperationCanceledException()))
        |> ignore)
    |> ignore
    Assert.Empty collector.Events

[<Fact>]
let ``captureAsync records a fault and returns it`` () =
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty

    let result =
        Aegis.captureAsync config scope classify (fun () -> async { return failwith "timeout" })
        |> Async.RunSynchronously

    match result with
    | Ok _ -> failwith "expected a fault"
    | Result.Error fault -> Assert.Equal(IntegrationFailure, fault.Category)

[<Fact>]
let ``captureAsync does not convert cancellation into a fault`` () =
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty

    Assert.Throws<OperationCanceledException>(fun () ->
        Aegis.captureAsync config scope classify (fun () -> async { return raise (OperationCanceledException()) })
        |> Async.RunSynchronously
        |> ignore)
    |> ignore

    Assert.Empty collector.Events

[<Fact>]
let ``suppression is recorded rather than silent`` () =
    // Requirement: core 7.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Aegis.suppress config (classify scope (Exception "boom")) "offline mode: retry queued" |> ignore
    let payload = List.head collector.Events
    Assert.Contains("\"eventType\":\"FaultSuppressed\"", payload)
    Assert.Contains("offline mode: retry queued", payload)

// --------------------------------------------------------------------- scopes

[<Fact>]
let ``faults inherit scope context`` () =
    // Requirement: additional 1.
    let config = configWith []
    let scope = Aegis.scope config "Chrona.Entry.Save" (Map [ "repository", Public "aegis" ])
    let fault = classify scope (Exception "boom")
    Assert.Equal(Public "aegis", fault.Context.["repository"])
    Assert.Equal("Chrona.Entry.Save", fault.Operation)

[<Fact>]
let ``nested scopes keep one correlation id across layers`` () =
    // Requirement: core 14.
    let config = configWith []
    let outer = Aegis.scope config "Chrona.Command.Refresh" (Map [ "user", Public "kevin" ])
    let inner = Aegis.nest outer "GitHub.GetFile" (Map [ "path", Public "entries.json" ])
    Assert.Equal(outer.CorrelationId, inner.CorrelationId)
    Assert.Equal(Public "kevin", inner.Context.["user"])
    Assert.Equal(Public "entries.json", inner.Context.["path"])

[<Fact>]
let ``nested scope context overrides the parent on conflict`` () =
    let config = configWith []
    let outer = Aegis.scope config "outer" (Map [ "stage", Public "load" ])
    let inner = Aegis.nest outer "inner" (Map [ "stage", Public "parse" ])
    Assert.Equal(Public "parse", inner.Context.["stage"])

// ----------------------------------------------------------------- sink runtime

[<Fact>]
let ``one failing sink does not prevent the others`` () =
    // Requirement: logging 15.
    let collector = Sinks.Collector()
    let config = { configWith [ Sinks.failing "github" Sinks.Optional; collector.Sink() ] with Fallback = ignore }
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    let report = Aegis.report config (FaultRecorded(classify scope (Exception "boom")))
    Assert.Single collector.Events |> ignore
    Assert.True report.FallbackUsed
    Assert.Equal(2, List.length report.Outcomes)

[<Fact>]
let ``sink failure reaches the fallback exactly once`` () =
    // Requirements: core 25, logging 16 -- bounded, no recursion.
    let calls = ref 0
    let config =
        { configWith [ Sinks.failing "a" Sinks.Optional; Sinks.failing "b" Sinks.Optional ] with
            Fallback = fun _ -> System.Threading.Interlocked.Increment calls |> ignore }

    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Aegis.report config (FaultRecorded(classify scope (Exception "boom"))) |> ignore
    Assert.Equal(1, calls.Value)

[<Fact>]
let ``a failing fallback cannot crash the caller`` () =
    // Requirement: core 25 -- Aegis survives its own failures.
    let config =
        { configWith [ Sinks.failing "github" Sinks.Optional ] with
            Fallback = fun _ -> failwith "even the fallback is broken" }

    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    let report = Aegis.report config (FaultRecorded(classify scope (Exception "boom")))
    Assert.True report.FallbackUsed

[<Fact>]
let ``required sink failure is distinguished from optional`` () =
    // Requirement: additional 50.
    let scope = Aegis.scope (configWith []) "Chrona.TimeEntry.Load" Map.empty
    let fault = classify scope (Exception "boom")

    let optional = configWith [ Sinks.failing "telemetry" Sinks.Optional ]
    Assert.False (Aegis.report optional (FaultRecorded fault)).RequiredFailed

    let required = configWith [ Sinks.failing "audit" Sinks.Required ]
    Assert.True (Aegis.report required (FaultRecorded fault)).RequiredFailed

[<Fact>]
let ``local history is bounded`` () =
    // Requirement: core 22.
    let collector = Sinks.Collector(capacity = 3)
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    for _ in 1..10 do
        Aegis.report config (FaultRecorded(classify scope (Exception "boom"))) |> ignore
    Assert.Equal(3, List.length collector.Events)

[<Fact>]
let ``tests assert on collected faults rather than console output`` () =
    // Requirement: core 27.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    Aegis.report config (FaultRecorded(classify scope (Exception "boom"))) |> ignore
    Assert.Contains("CHRONA.GITHUB.LOAD_FAILED", collector.Codes)
