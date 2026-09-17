module Aegis.Tests.Compatibility

open System
open System.Collections.Concurrent
open System.Threading.Tasks
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 13, 0, 0, TimeSpan.Zero)

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

let private config sinks =
    { Application = "Chrona"
      Version = None
      Sinks = sinks
      Rules = Redaction.defaultRules
      Fallback = ignore
      Persistence = Blocking
      Now = fun () -> at
      Random =
        let counter = ref 0L
        fun () ->
            let n = System.Threading.Interlocked.Increment counter
            n, n * 31L }

// ------------------------------------------------------ backwards compatibility

[<Fact>]
let ``the event schema identifier is stable`` () =
    // Requirements: core 37, logging 12. Changing this is a deliberate,
    // visible act, not an accident of refactoring.
    Assert.Equal("aegis/event/v1", Schema.Event)
    Assert.Equal("aegis/fault/v1", Schema.Fault)

[<Fact>]
let ``an event carrying unknown future fields is still readable`` () =
    // Requirement: logging 12 -- schema evolution must not break consumers.
    let future =
        """{"schema":"aegis/event/v2","eventId":"01E1","eventType":"FaultRecorded",
            "faultId":"01F1","correlationId":"CORR1","application":"Chrona",
            "operation":"Chrona.TimeEntry.Load","code":"CHRONA.GITHUB.LOAD_FAILED",
            "severity":"Warning","timestamp":"2026-09-17T13:00:00.000Z",
            "somethingAddedLater":{"nested":true},"anotherNewField":[1,2,3]}"""

    match Store.index future with
    | Ok indexed ->
        Assert.Equal(EventId "01E1", indexed.EventId)
        Assert.Equal(Some(FaultId "01F1"), indexed.FaultId)
        Assert.Equal(Some(FaultCode "CHRONA.GITHUB.LOAD_FAILED"), indexed.Code)
    | Result.Error e -> failwith $"a future event should still index, got {e}"

[<Fact>]
let ``an older event missing optional fields is still readable`` () =
    // Backwards compatibility: an early record lacking fields added later.
    let old = """{"schema":"aegis/event/v1","eventId":"01E0","eventType":"FaultRecorded"}"""

    match Store.index old with
    | Ok indexed ->
        Assert.Equal(EventId "01E0", indexed.EventId)
        Assert.True indexed.FaultId.IsNone
        Assert.True indexed.Timestamp.IsNone
    | Result.Error e -> failwith $"an older event should still index, got {e}"

[<Fact>]
let ``a query tolerates events that lack the field being filtered`` () =
    // A stored record from before a field existed must not match a filter on
    // that field, and must not blow up the query either.
    let old = """{"schema":"aegis/event/v1","eventId":"01E0","eventType":"FaultRecorded"}"""

    match Store.index old with
    | Ok indexed ->
        Assert.False(Store.matches { Store.anyEvent with Code = Some(FaultCode "ANY.CODE") } indexed)
        Assert.True(Store.matches Store.anyEvent indexed)
    | Result.Error e -> failwith $"{e}"

[<Fact>]
let ``an event with an unrecognized severity still indexes`` () =
    // Tooling must not break because a later version added a severity.
    let future =
        """{"schema":"aegis/event/v1","eventId":"01E1","eventType":"FaultRecorded","severity":"Catastrophic"}"""

    match Store.index future with
    | Ok indexed -> Assert.Equal(Some "Catastrophic", indexed.Severity)
    | Result.Error e -> failwith $"{e}"

[<Fact>]
let ``every current event type round-trips through the index`` () =
    // Guards against a new event type that cannot be read back.
    let events =
        [ FaultRecorded fault
          FaultSuppressed(fault, "throttled")
          FaultRepeated(fault.Id, at)
          FaultAcknowledged(fault.Id, Operator, at)
          FaultEscalated(fault.Id, Warning, Critical, at)
          FaultResolved(fault.Id, { Timestamp = at; Kind = ResolvedAutomatically; Action = None; Verified = true })
          FaultReopened(fault.Id, at, "recurred")
          FaultSuperseded(fault.Id, FaultId "01F2", at)
          RecoveryStarted(
              fault.Id,
              { Action = Reload
                AttemptNumber = 1
                Actor = Agent
                Timestamp = at
                CorrelationId = fault.CorrelationId
                Outcome = AwaitingVerification }
          )
          RecoveryConcluded(fault.Id, 1, Succeeded, at)
          SinkFailed("github", FaultCode "AEGIS.SINK.WRITE_FAILED", "unreachable") ]

    for ev in events do
        let payload = Serialization.event Redaction.defaultRules (EventId "01E1") ev

        match Store.index payload with
        | Ok indexed -> Assert.Equal(Serialization.eventTypeName ev, indexed.EventType)
        | Result.Error e -> failwith $"{Serialization.eventTypeName ev} did not index: {e}"

// ------------------------------------------------------------------ concurrency

[<Fact>]
let ``concurrent writes to a sink lose nothing`` () =
    // Requirement: logging 34 -- sinks must tolerate concurrent writes.
    let collector = Sinks.Collector(capacity = 1000)
    let sink = collector.Sink()

    Parallel.For(0, 200, fun n -> sink.Write $"{{\"eventId\":\"E{n}\"}}" |> Async.RunSynchronously) |> ignore

    Assert.Equal(200, List.length collector.Events)

[<Fact>]
let ``concurrent reports produce distinct event identities`` () =
    // Requirements: logging 24, 34 -- identity must survive concurrency.
    let collector = Sinks.Collector(capacity = 1000)
    let cfg = config [ collector.Sink() ]

    Parallel.For(0, 200, fun _ -> Aegis.report cfg (FaultRecorded fault) |> ignore) |> ignore

    let ids =
        collector.Events
        |> List.choose (fun payload ->
            match Store.index payload with
            | Ok indexed -> Some indexed.EventId
            | Result.Error _ -> None)

    Assert.Equal(200, List.length ids)
    Assert.Equal(200, ids |> List.distinct |> List.length)

[<Fact>]
let ``a bounded sink under concurrent load stays within its limit`` () =
    // Bounded history must hold under concurrency too. Requirement: core 22.
    let collector = Sinks.Collector(capacity = 50)
    let sink = collector.Sink()

    Parallel.For(0, 500, fun n -> sink.Write $"{{\"eventId\":\"E{n}\"}}" |> Async.RunSynchronously) |> ignore

    Assert.True(List.length collector.Events <= 50, $"expected at most 50, got {List.length collector.Events}")

[<Fact>]
let ``concurrent deliveries each report their own outcome`` () =
    // Requirement: logging 15 -- independence holds under concurrency.
    let collector = Sinks.Collector(capacity = 1000)
    let reports = ConcurrentBag<Sinks.Report>()

    let cfg =
        { config [ Sinks.failing "github" Sinks.Optional; collector.Sink() ] with Fallback = ignore }

    Parallel.For(0, 100, fun _ -> reports.Add(Aegis.report cfg (FaultRecorded fault))) |> ignore

    Assert.Equal(100, reports.Count)
    // Every delivery saw the same shape: one failure, one success, fallback used.
    Assert.All(reports, fun r ->
        Assert.Equal(2, List.length r.Outcomes)
        Assert.True r.FallbackUsed
        Assert.False r.RequiredFailed)

    Assert.Equal(100, List.length collector.Events)

[<Fact>]
let ``the store tolerates concurrent appends of distinct events`` () =
    // Requirement: logging 34 -- GitHub strategy must minimize conflicts when
    // several agents or sessions record at once.
    let files = ConcurrentDictionary<string, string>()

    let ops =
        { Aegis.Store.GitHub.GitHubStore.Exists = fun path -> async { return Ok(files.ContainsKey path) }
          Aegis.Store.GitHub.GitHubStore.PutFile =
            fun path content _ ->
                async { return if files.TryAdd(path, content) then Ok() else Result.Error "already exists" }
          Aegis.Store.GitHub.GitHubStore.PutFiles =
            fun entries _ ->
                async {
                    let added = entries |> List.forall (fun (path, content) -> files.TryAdd(path, content))
                    return if added then Ok() else Result.Error "already exists"
                }
          Aegis.Store.GitHub.GitHubStore.ListPrefix =
            fun prefix ->
                async {
                    return
                        files
                        |> Seq.filter (fun kv -> kv.Key.StartsWith prefix)
                        |> Seq.map (fun kv -> kv.Key, kv.Value)
                        |> List.ofSeq
                        |> Ok
                } }

    let store =
        Aegis.Store.GitHub.GitHubStore.create
            { Aegis.Store.GitHub.GitHubStore.defaults "kemiller2002" "aegis" with Now = fun () -> at }
            ops

    let payload n =
        Serialization.event Redaction.defaultRules (EventId $"01E{n}") (FaultRecorded { fault with Id = FaultId $"01F{n}" })

    Parallel.For(0, 100, fun n -> store.Append (EventId $"01E{n}") (payload n) |> Async.RunSynchronously |> ignore)
    |> ignore

    Assert.Equal(100, files.Count)

[<Fact>]
let ``concurrent appends of the same event id persist it only once`` () =
    // Requirement: logging 32, 36 -- duplicate-write protection, and never a
    // silent overwrite.
    let files = ConcurrentDictionary<string, string>()
    let writes = ref 0

    let ops =
        { Aegis.Store.GitHub.GitHubStore.Exists = fun path -> async { return Ok(files.ContainsKey path) }
          Aegis.Store.GitHub.GitHubStore.PutFile =
            fun path content _ ->
                async {
                    if files.TryAdd(path, content) then
                        System.Threading.Interlocked.Increment writes |> ignore
                        return Ok()
                    else
                        return Result.Error "already exists"
                }
          Aegis.Store.GitHub.GitHubStore.PutFiles = fun _ _ -> async { return Result.Error "not used" }
          Aegis.Store.GitHub.GitHubStore.ListPrefix = fun _ -> async { return Ok [] } }

    let store =
        Aegis.Store.GitHub.GitHubStore.create
            { Aegis.Store.GitHub.GitHubStore.defaults "kemiller2002" "aegis" with Now = fun () -> at }
            ops

    let payload = Serialization.event Redaction.defaultRules (EventId "01SAME") (FaultRecorded fault)

    Parallel.For(0, 50, fun _ -> store.Append (EventId "01SAME") payload |> Async.RunSynchronously |> ignore)
    |> ignore

    // Exactly one write won; the rest were refused rather than overwriting.
    Assert.Equal(1, writes.Value)
    Assert.Equal(1, files.Count)
