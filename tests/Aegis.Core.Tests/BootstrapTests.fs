module Aegis.Tests.Bootstrap

open System
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 8, 0, 0, TimeSpan.Zero)

let private baseConfig sinks =
    { Application = "Chrona"
      Version = Some "1.4.2"
      Sinks = sinks
      Rules = Redaction.defaultRules
      Fallback = ignore
      Persistence = Blocking
      Now = fun () -> at
      Random =
        let counter = ref 0L
        fun () ->
            let n = System.Threading.Interlocked.Increment counter
            n, n * 3L }

let private durableSink name level =
    { Sinks.Name = name
      Sinks.Level = level
      Sinks.Capabilities = [ Sinks.SupportsDurableWrite ]
      Sinks.WriteBatch = None
      Sinks.Write = fun _ -> async { return () } }

// ------------------------------------------------------- configuration validation

[<Fact>]
let ``a sound configuration validates`` () =
    match Bootstrap.validate (Some 100) (baseConfig [ durableSink "github" Sinks.Required ]) with
    | Ok _ -> ()
    | Result.Error problems -> failwith $"expected success, got {problems}"

[<Fact>]
let ``duplicate sink identifiers are rejected`` () =
    // Requirement: additional 47.
    let config = baseConfig [ durableSink "github" Sinks.Optional; durableSink "github" Sinks.Optional ]

    match Bootstrap.validate None config with
    | Result.Error problems -> Assert.Contains(Bootstrap.DuplicateSinkName "github", problems)
    | Ok _ -> failwith "expected a duplicate-sink problem"

[<Fact>]
let ``a configuration with no sinks is rejected`` () =
    match Bootstrap.validate None (baseConfig []) with
    | Result.Error problems -> Assert.Contains(Bootstrap.NoSinksConfigured, problems)
    | Ok _ -> failwith "expected a no-sinks problem"

[<Fact>]
let ``a missing application name is rejected`` () =
    match Bootstrap.validate None { baseConfig [ durableSink "s" Sinks.Optional ] with Application = "  " } with
    | Result.Error problems -> Assert.Contains(Bootstrap.MissingApplicationName, problems)
    | Ok _ -> failwith "expected a missing-application problem"

[<Fact>]
let ``a required sink that cannot write durably is rejected`` () =
    // Requirements: additional 48, 50 -- "required" must mean something.
    let flimsy =
        { Sinks.Name = "audit"
          Sinks.Level = Sinks.Required
          Sinks.Capabilities = [ Sinks.SupportsQuery ]
          Sinks.WriteBatch = None
          Sinks.Write = fun _ -> async { return () } }

    match Bootstrap.validate None (baseConfig [ flimsy ]) with
    | Result.Error problems -> Assert.Contains(Bootstrap.RequiredSinkWithoutDurableWrite "audit", problems)
    | Ok _ -> failwith "expected a durability problem"

[<Fact>]
let ``an optional sink without durable writes is accepted`` () =
    let telemetry =
        { Sinks.Name = "telemetry"
          Sinks.Level = Sinks.Optional
          Sinks.Capabilities = []
          Sinks.WriteBatch = None
          Sinks.Write = fun _ -> async { return () } }

    match Bootstrap.validate None (baseConfig [ telemetry ]) with
    | Ok _ -> ()
    | Result.Error problems -> failwith $"expected success, got {problems}"

[<Fact>]
let ``an invalid redaction rule is rejected`` () =
    let config =
        { baseConfig [ durableSink "s" Sinks.Optional ] with
            Rules = [ { Name = " "; AppliesTo = fun _ -> true } ] }

    match Bootstrap.validate None config with
    | Result.Error problems -> Assert.Contains(Bootstrap.RedactionRuleWithoutName, problems)
    | Ok _ -> failwith "expected a redaction problem"

[<Fact>]
let ``a non-positive queue capacity is rejected`` () =
    match Bootstrap.validate (Some 0) (baseConfig [ durableSink "s" Sinks.Optional ]) with
    | Result.Error problems -> Assert.Contains(Bootstrap.InvalidQueueCapacity 0, problems)
    | Ok _ -> failwith "expected a capacity problem"

[<Fact>]
let ``validation reports every problem rather than only the first`` () =
    // Requirement: additional 47 -- one startup pass shows the whole picture.
    let config = { baseConfig [] with Application = "" }

    match Bootstrap.validate (Some -1) config with
    | Result.Error problems ->
        Assert.Contains(Bootstrap.MissingApplicationName, problems)
        Assert.Contains(Bootstrap.NoSinksConfigured, problems)
        Assert.Contains(Bootstrap.InvalidQueueCapacity -1, problems)
    | Ok _ -> failwith "expected several problems"

[<Fact>]
let ``validation is pure and does not touch the sinks`` () =
    // Requirement: additional 47 -- no recursive initialization failure.
    let writes = ref 0

    let counting =
        { Sinks.Name = "counting"
          Sinks.Level = Sinks.Optional
          Sinks.Capabilities = [ Sinks.SupportsDurableWrite ]
          Sinks.WriteBatch = None
          Sinks.Write = fun _ -> async { System.Threading.Interlocked.Increment writes |> ignore } }

    Bootstrap.validate (Some 10) (baseConfig [ counting ]) |> ignore
    Assert.Equal(0, writes.Value)

[<Fact>]
let ``every configuration problem has a stable code and a message`` () =
    // Requirement: core 4 applied to configuration faults.
    let all =
        [ Bootstrap.MissingApplicationName
          Bootstrap.NoSinksConfigured
          Bootstrap.DuplicateSinkName "x"
          Bootstrap.RequiredSinkWithoutDurableWrite "x"
          Bootstrap.RedactionRuleWithoutName
          Bootstrap.InvalidQueueCapacity 0 ]

    for problem in all do
        let code, message = Bootstrap.describe problem
        Assert.StartsWith("AEGIS.CONFIG.", code.Value)
        Assert.False(String.IsNullOrWhiteSpace message)

// ------------------------------------------------------------- bootstrap mode

[<Fact>]
let ``faults can be recorded before any sink exists`` () =
    // Requirement: additional 20.
    let pending =
        Bootstrap.minimal 10
        |> Bootstrap.record at (FaultCode "AEGIS.CONFIG.LOAD_FAILED") "configuration file unreadable"
        |> Bootstrap.record at (FaultCode "AEGIS.LIMEN.STARTUP_FAILED") "Limen did not start"

    Assert.Equal(2, List.length pending.Entries)

[<Fact>]
let ``bootstrap diagnostics are bounded and count what they drop`` () =
    let pending =
        [ 1..10 ]
        |> List.fold (fun acc n -> Bootstrap.record at (FaultCode $"AEGIS.BOOT.{n}") $"problem {n}" acc) (Bootstrap.minimal 3)

    Assert.Equal(3, List.length pending.Entries)
    Assert.Equal(7, pending.Dropped)

[<Fact>]
let ``configuration problems become bootstrap diagnostics rather than throwing`` () =
    // Requirement: additional 47.
    match Bootstrap.validate None (baseConfig []) with
    | Result.Error problems ->
        let pending = Bootstrap.recordProblems at problems (Bootstrap.minimal 10)
        Assert.NotEmpty pending.Entries
        let _, message = pending.Entries.Head |> fun (_, c, m) -> c, m
        Assert.False(String.IsNullOrWhiteSpace message)
    | Ok _ -> failwith "expected problems"

[<Fact>]
let ``promoting bootstrap diagnostics delivers them to the configured sinks`` () =
    // Requirement: additional 20 -- promotable once initialization succeeds.
    let collector = Sinks.Collector()
    let config = baseConfig [ collector.Sink() ]

    let pending =
        Bootstrap.minimal 10
        |> Bootstrap.record at (FaultCode "AEGIS.CONFIG.LOAD_FAILED") "configuration file unreadable"

    let reports, cleared = Bootstrap.promote config "Chrona.Startup" pending

    Assert.Single reports |> ignore
    Assert.Single collector.Events |> ignore
    Assert.Contains("AEGIS.CONFIG.LOAD_FAILED", collector.Codes)
    Assert.Empty cleared.Entries

[<Fact>]
let ``promoted bootstrap faults are classified as configuration failures`` () =
    let collector = Sinks.Collector()
    let config = baseConfig [ collector.Sink() ]

    let pending =
        Bootstrap.minimal 10
        |> Bootstrap.record at (FaultCode "AEGIS.CONFIG.NO_SINKS") "no sinks"

    Bootstrap.promote config "Chrona.Startup" pending |> ignore
    let payload = List.head collector.Events
    Assert.Contains("\"category\":\"ConfigurationFailure\"", payload)
    Assert.Contains("\"phase\":\"bootstrap\"", payload)

// --------------------------------------------------------------------- shutdown

[<Fact>]
let ``shutdown flushes deferred events`` () =
    // Requirement: additional 21.
    let written = ResizeArray<string>()

    let queue =
        Offline.create 10
        |> Offline.enqueue (EventId "E1") "one"
        |> Offline.enqueue (EventId "E2") "two"

    let outcome = Bootstrap.shutdown written.Add queue (Bootstrap.minimal 10)

    Assert.Equal<string list>([ "one"; "two" ], List.ofSeq written)
    Assert.Equal(2, List.length outcome.Flushed)
    Assert.Equal(0, outcome.Unflushed)
    Assert.True outcome.Failure.IsNone

[<Fact>]
let ``a sink failing during shutdown does not loop and does not block exit`` () =
    // Requirement: additional 21 -- no recursive or indefinite shutdown loop.
    let attempts = ref 0

    let write _ =
        System.Threading.Interlocked.Increment attempts |> ignore
        failwith "sink already closed"

    let queue =
        Offline.create 10
        |> Offline.enqueue (EventId "E1") "one"
        |> Offline.enqueue (EventId "E2") "two"

    let outcome = Bootstrap.shutdown write queue (Bootstrap.minimal 10)

    // Exactly one attempt: it stopped at the first failure rather than retrying.
    Assert.Equal(1, attempts.Value)
    Assert.Equal(2, outcome.Unflushed)
    Assert.True outcome.Failure.IsSome

[<Fact>]
let ``shutdown reports diagnostics it could not promote`` () =
    let pending =
        Bootstrap.minimal 10
        |> Bootstrap.record at (FaultCode "AEGIS.SHUTDOWN.STATE_WRITE_FAILED") "final write failed"

    let outcome = Bootstrap.shutdown ignore (Offline.create 10) pending
    Assert.Equal(1, outcome.Abandoned)
