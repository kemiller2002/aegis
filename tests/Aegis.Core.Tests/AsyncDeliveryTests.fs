module Aegis.Tests.AsyncDelivery

open System
open System.Diagnostics
open System.Threading
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 14, 0, 0, TimeSpan.Zero)

let private fault =
    { Id = FaultId "01F1"
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = None
      Operation = "Chrona.TimeEntry.Load"
      Category = IntegrationFailure
      Code = FaultCode "CHRONA.GITHUB.LOAD_FAILED"
      Severity = Warning
      Impact = OperationOnly
      Domain = IntegrationDomain
      Radius = OneOperation
      Retention = DiagnosticOnly
      Persistence = Transient
      Owner = None
      Dependencies = [ "Chrona" ]
      UserMessage = "GitHub could not be reached."
      TechnicalDetails = None
      Context = Map.empty
      Recovery = NoRecovery
      Diagnostics = noDiagnostics
      Cause = None }

let private configWith mode sinks =
    { Application = "Chrona"
      Version = None
      Sinks = sinks
      Rules = Redaction.defaultRules
      Fallback = ignore
      Persistence = mode
      Now = fun () -> at
      Random =
        let counter = ref 0L
        fun () ->
            let n = Interlocked.Increment counter
            n, n * 17L }

/// A sink that blocks inside its write until the test releases it, and
/// records whether it finished. Gates rather than sleeps, so these tests
/// assert the actual ordering semantics instead of wall-clock timings, which
/// are unreliable while the rest of the suite runs in parallel.
type private GatedSink() =
    let started = new ManualResetEventSlim(false)
    let gate = new ManualResetEventSlim(false)
    let completed = ref 0

    member _.Started = started
    member _.Release() = gate.Set()
    member _.Completed = completed.Value > 0

    member _.Sink =
        { Sinks.Name = "gated"
          Sinks.Level = Sinks.Optional
          Sinks.Capabilities = [ Sinks.SupportsDurableWrite ]
          Sinks.WriteBatch = None
          Sinks.Write =
            fun _ ->
                async {
                    started.Set()
                    gate.Wait(TimeSpan.FromSeconds 10.) |> ignore
                    Interlocked.Increment completed |> ignore
                } }

// ------------------------------------------------------------ non-blocking path

[<Fact>]
let ``detached reporting returns before the sink completes`` () =
    // Requirement: logging 18 -- Aegis must not block normal application
    // execution on slow remote storage.
    let sink = GatedSink()
    let config = configWith Detached [ sink.Sink ]

    Aegis.reportDetached config (FaultRecorded fault)

    // The caller is back while the sink is still inside its write.
    Assert.False(sink.Completed, "reporting waited for the sink to finish")
    Assert.True(sink.Started.Wait(TimeSpan.FromSeconds 10.), "the sink was never written to")
    sink.Release()

[<Fact>]
let ``capture does not block on persistence by default`` () =
    // Requirements: logging 17, 18 -- a slow or failing sink must not be paid
    // for by the primary operation.
    let sink = GatedSink()
    let config = configWith Detached [ sink.Sink ]
    let scope = Aegis.scope config "Chrona.TimeEntry.Load" Map.empty
    let classify _ _ = fault

    let result = Aegis.capture config scope classify (fun () -> failwith "GitHub unreachable")

    match result with
    | Result.Error f -> Assert.Equal(fault.Code, f.Code)
    | Ok _ -> failwith "expected a fault"

    Assert.False(sink.Completed, "capture waited for persistence")
    Assert.True(sink.Started.Wait(TimeSpan.FromSeconds 10.), "the fault was never delivered")
    sink.Release()

[<Fact>]
let ``blocking mode waits, which is what audit-required persistence needs`` () =
    // Requirement: logging 17 -- the carve-out must be explicitly configured.
    let sink = GatedSink()
    let config = configWith Blocking [ sink.Sink ]

    // Open the gate first: blocking mode must still have completed the write
    // by the time it returns.
    sink.Release()
    Aegis.report config (FaultRecorded fault) |> ignore

    Assert.True(sink.Completed, "blocking mode returned before the sink finished")

[<Fact>]
let ``sinks are attempted concurrently, so one cannot delay another`` () =
    // Requirements: logging 15, 18. Each sink waits for the other to start;
    // if delivery were serialized, the first would time out and report false.
    let firstStarted = new ManualResetEventSlim(false)
    let secondStarted = new ManualResetEventSlim(false)
    let firstSawSecond = ref false
    let secondSawFirst = ref false

    let pairSink name (mine: ManualResetEventSlim) (theirs: ManualResetEventSlim) (sawThem: bool ref) =
        { Sinks.Name = name
          Sinks.Level = Sinks.Optional
          Sinks.Capabilities = []
          Sinks.WriteBatch = None
          Sinks.Write =
            fun _ ->
                async {
                    mine.Set()
                    sawThem.Value <- theirs.Wait(TimeSpan.FromSeconds 10.)
                } }

    let config =
        configWith
            Blocking
            [ pairSink "first" firstStarted secondStarted firstSawSecond
              pairSink "second" secondStarted firstStarted secondSawFirst ]

    Aegis.report config (FaultRecorded fault) |> ignore

    Assert.True(firstSawSecond.Value && secondSawFirst.Value, "sinks were serialized rather than attempted in parallel")

[<Fact>]
let ``a failing sink in detached mode cannot throw into the caller`` () =
    // Requirement: core 25 -- Aegis survives its own failures.
    let config = configWith Detached [ Sinks.failing "github" Sinks.Optional ]
    Aegis.reportDetached config (FaultRecorded fault)
    // Reaching here without an exception is the assertion; the detached work
    // fails on its own thread and is contained.
    Assert.True true

// ------------------------------------------------------------------- batching

[<Fact>]
let ``a batch-capable sink receives one batch rather than N writes`` () =
    // Requirement: logging 19.
    let singles = ref 0
    let batches = ref 0
    let received = ref 0

    let batching =
        { Sinks.Name = "batching"
          Sinks.Level = Sinks.Optional
          Sinks.Capabilities = [ Sinks.SupportsBatch ]
          Sinks.WriteBatch =
            Some(fun payloads ->
                async {
                    Interlocked.Increment batches |> ignore
                    Interlocked.Add(received, List.length payloads) |> ignore
                })
          Sinks.Write = fun _ -> async { Interlocked.Increment singles |> ignore } }

    let config = configWith Blocking [ batching ]
    let events = List.replicate 5 (FaultRecorded fault)
    Aegis.reportBatch config events |> ignore

    Assert.Equal(1, batches.Value)
    Assert.Equal(5, received.Value)
    Assert.Equal(0, singles.Value)

[<Fact>]
let ``a sink without batch support still receives every event in order`` () =
    // Requirement: logging 19 -- batching must not lose identity or ordering.
    let collector = Sinks.Collector(capacity = 100)
    let config = configWith Blocking [ collector.Sink() ]

    let events =
        [ for n in 1..4 -> FaultRecorded { fault with Id = FaultId $"01F{n}" } ]

    Aegis.reportBatch config events |> ignore

    let ids =
        collector.Events
        |> List.choose (fun p ->
            match Store.index p with
            | Ok i -> i.FaultId |> Option.map (fun f -> f.Value)
            | Result.Error _ -> None)

    Assert.Equal<string list>([ "01F1"; "01F2"; "01F3"; "01F4" ], ids)

[<Fact>]
let ``a batch reports failure without losing the other sinks`` () =
    let collector = Sinks.Collector(capacity = 100)
    let config = configWith Blocking [ Sinks.failing "github" Sinks.Optional; collector.Sink() ]
    let report = Aegis.reportBatch config (List.replicate 3 (FaultRecorded fault))

    Assert.True report.FallbackUsed
    Assert.Equal(3, List.length collector.Events)

// --------------------------------------------------------------- sink health

[<Fact>]
let ``sink health is derived from observed outcomes`` () =
    // Requirement: logging 38.
    let observations =
        [ at, Sinks.Written "github"
          at.AddSeconds 1., Sinks.Written "github"
          at.AddSeconds 2., Sinks.Failed("github", Sinks.Optional, "unreachable") ]

    let health = Sinks.observe observations
    let github = health.["github"]
    Assert.Equal(2, github.Writes)
    Assert.Equal(1, github.Failures)
    Assert.Equal(Sinks.SinkDegraded, github.State)
    Assert.Equal(Some(at.AddSeconds 1.), github.LastSuccess)

[<Fact>]
let ``a sink that has never succeeded reads as unavailable`` () =
    let health = Sinks.observe [ at, Sinks.Failed("github", Sinks.Required, "unreachable") ]
    Assert.Equal(Sinks.SinkUnavailable, health.["github"].State)

[<Fact>]
let ``recovering after a failure returns a sink to available`` () =
    let health =
        Sinks.observe
            [ at, Sinks.Written "github"
              at.AddSeconds 1., Sinks.Failed("github", Sinks.Optional, "blip")
              at.AddSeconds 2., Sinks.Written "github" ]

    Assert.Equal(Sinks.Available, health.["github"].State)

[<Fact>]
let ``health observations can be taken straight from delivery reports`` () =
    let collector = Sinks.Collector()
    let config = configWith Blocking [ Sinks.failing "github" Sinks.Optional; collector.Sink() ]
    let report = Aegis.report config (FaultRecorded fault)
    let health = Sinks.observe (Sinks.observationsOf at [ report ])

    Assert.Equal(Sinks.SinkUnavailable, health.["github"].State)
    Assert.Equal(Sinks.Available, health.["collector"].State)

// ---------------------------------------------------------- health projection

let private healthOf entries = Sinks.observe entries

[<Fact>]
let ``health is healthy when every sink is writing`` () =
    // Requirement: additional 51.
    let projection = Health.project false 100 0 (healthOf [ at, Sinks.Written "github" ])
    Assert.Equal(Health.Healthy, projection.State)
    Assert.True(Health.persistenceTrustworthy projection)

[<Fact>]
let ``bootstrap wins over everything else`` () =
    // Requirement: additional 20, 51 -- nothing else is trustworthy yet.
    let projection = Health.project true 100 0 Map.empty
    Assert.Equal(Health.BootstrapOnly, projection.State)
    Assert.False(Health.persistenceTrustworthy projection)

[<Fact>]
let ``a broken required sink is critical`` () =
    // Requirement: additional 50 -- the operating mode depends on it.
    let projection =
        Health.project false 100 0 (healthOf [ at, Sinks.Failed("audit", Sinks.Required, "down") ])

    Assert.Equal(Health.CriticalFailure, projection.State)

[<Fact>]
let ``a broken optional sink is only degraded`` () =
    let projection =
        Health.project
            false
            100
            0
            (healthOf [ at, Sinks.Written "collector"; at, Sinks.Failed("telemetry", Sinks.Optional, "down") ])

    Assert.Equal(Health.Degraded, projection.State)

[<Fact>]
let ``no working sink at all reads as persistence unavailable`` () =
    let projection =
        Health.project false 100 0 (healthOf [ at, Sinks.Failed("github", Sinks.Optional, "down") ])

    Assert.Equal(Health.PersistenceUnavailable, projection.State)
    Assert.False(Health.persistenceTrustworthy projection)

[<Fact>]
let ``a deep queue reads as backlogged`` () =
    let projection = Health.project false 10 250 (healthOf [ at, Sinks.Written "github" ])
    Assert.Equal(Health.QueueBacklogged, projection.State)
    // Still trustworthy: the events are not lost, just not yet durable.
    Assert.True(Health.persistenceTrustworthy projection)

[<Fact>]
let ``the projection reports the queue depth it was given`` () =
    let projection = Health.project false 100 7 Map.empty
    Assert.Equal(7, projection.Queued)
