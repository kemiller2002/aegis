module Aegis.Tests.FailureSemantics

// Explicit failure semantics (aegis#13, AEGIS-QUAL-002..006).
//
// Every test here pins one rule from the same contract: a failure is either
// returned, recorded, or explicitly classified as "not a failure" -- it is
// never dropped, and partial or unconfirmed persistence never reads as
// success.

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Text.RegularExpressions
open System.Threading.Tasks
open Xunit
open Aegis
open Aegis.Integration.GitHub

let private at = DateTimeOffset(2026, 10, 5, 9, 0, 0, TimeSpan.Zero)

let private configWith persistence sinks =
    { Application = "Praxis"
      Version = Some "1.0.0"
      Sinks = sinks
      Rules = Redaction.defaultRules
      Fallback = ignore
      Persistence = persistence
      Now = fun () -> at
      Random =
        let counter = ref 0L
        fun () ->
            let n = Threading.Interlocked.Increment counter
            n, n * 13L }

let private classify (scope: Scope) (ex: exn) =
    Aegis.faultOf
        (configWith Blocking [])
        scope
        (FaultCode "PRAXIS.REMOTE.CALL_FAILED")
        IntegrationFailure
        FaultSeverity.Error
        OperationOnly
        Transient
        NoRecovery
        "The remote call failed."
        ex

/// The exception shape HttpClient raises on its own timeout since .NET 5: a
/// TaskCanceledException whose inner exception is a TimeoutException, and
/// whose token was never cancelled by the caller.
let private httpClientTimeout () =
    TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 0.1 seconds elapsing.", TimeoutException "timed out")

// ------------------------------------------------- 1. timeout is not cancellation

[<Fact>]
let ``an HttpClient timeout is a fault, not a caller cancellation`` () =
    let collector = Sinks.Collector()
    let config = configWith Blocking [ collector.Sink() ]
    let scope = Aegis.scope config "Praxis.Remote.Fetch" Map.empty

    match Aegis.capture config scope classify (fun () -> raise (httpClientTimeout ())) with
    | Result.Error fault -> Assert.Equal(FaultCode "PRAXIS.REMOTE.CALL_FAILED", fault.Code)
    | Ok _ -> failwith "a timeout must not read as success"

    Assert.Single collector.Events |> ignore

[<Fact>]
let ``captureAsync returns a fault for an HttpClient timeout`` () =
    let collector = Sinks.Collector()
    let config = configWith Blocking [ collector.Sink() ]
    let scope = Aegis.scope config "Praxis.Remote.Fetch" Map.empty

    let result =
        Aegis.captureAsync config scope classify (fun () -> async { return raise (httpClientTimeout ()) })
        |> Async.RunSynchronously

    Assert.True(Result.isError result)
    Assert.Single collector.Events |> ignore

[<Fact>]
let ``the top-level guard records an HttpClient timeout instead of dropping it`` () =
    let collector = Sinks.Collector()
    let config = configWith Blocking [ collector.Sink() ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty

    Aegis.guard config scope classify (fun () -> raise (httpClientTimeout ()))

    Assert.Single collector.Events |> ignore

[<Fact>]
let ``the GitHub integration classifies an HttpClient timeout as Timeout`` () =
    Assert.Equal(GitHubFailure.Timeout, GitHubFailure.ofException (httpClientTimeout ()))
    Assert.Equal(FaultCode "AEGIS.NETWORK.TIMEOUT", GitHubFailure.code (GitHubFailure.ofException (httpClientTimeout ())))

[<Fact>]
let ``a real HttpClient timeout reaches the fault model through capture`` () =
    // Not a simulated exception: a loopback listener accepts the connection
    // and never answers, so HttpClient's own Timeout fires.
    let listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()

    try
        let port = (listener.LocalEndpoint :?> IPEndPoint).Port
        let accepted = listener.AcceptSocketAsync()
        use client = new Http.HttpClient(Timeout = TimeSpan.FromMilliseconds 200.)

        let collector = Sinks.Collector()
        let config = configWith Blocking [ collector.Sink() ]
        let scope = Aegis.scope config "Praxis.Remote.Fetch" Map.empty

        let result =
            Aegis.capture config scope classify (fun () ->
                client.GetAsync($"http://127.0.0.1:{port}/").GetAwaiter().GetResult())

        Assert.True(Result.isError result, "a timed-out request must come back as a fault")
        Assert.Single collector.Events |> ignore
        accepted.Wait(TimeSpan.FromSeconds 5.) |> ignore
    finally
        listener.Stop()

[<Fact>]
let ``a caller cancellation is still not a fault`` () =
    // Core 29 is unchanged: a cancellation the caller asked for is not a failure.
    use source = new Threading.CancellationTokenSource()
    source.Cancel()
    let cancelled = OperationCanceledException(source.Token)
    Assert.True(Aegis.isCancellation cancelled)
    Assert.True(Aegis.isCancellation (TaskCanceledException()))

// --------------------------------------------- 2. required sink failure visibility

[<Fact>]
let ``characterization: capture alone cannot tell a persisted fault from an unpersisted one`` () =
    // `capture` returns the fault, not the delivery outcome. This is kept for
    // compatibility; the explicit path is `captureReported`.
    let scope cfg = Aegis.scope cfg "Praxis.Audit.Write" Map.empty
    let healthy = configWith Blocking [ Sinks.noOp ]
    let broken = configWith Blocking [ Sinks.failing "audit" Sinks.Required ]

    let shape result =
        match result with
        | Result.Error (fault: Fault) -> fault.Code.Value
        | Ok () -> "ok"

    Assert.Equal(
        shape (Aegis.capture healthy (scope healthy) classify (fun () -> failwith "boom")),
        shape (Aegis.capture broken (scope broken) classify (fun () -> failwith "boom"))
    )

// ------------------------------------------------- 6. detached delivery window

[<Fact>]
let ``characterization: detached capture returns before the sink has written`` () =
    // The default persistence mode is Detached. A short-lived process that
    // exits right after capture can lose the event; `flush` and
    // `forCommandLine` exist so that loss is preventable and observable.
    let gate = new Threading.ManualResetEventSlim(false)
    let written = ref 0

    let slow =
        { Sinks.noOp with
            Name = "slow"
            Write =
                fun _ ->
                    async {
                        let! _ = Async.AwaitWaitHandle gate.WaitHandle
                        Threading.Interlocked.Increment written |> ignore
                    } }

    let config = configWith Detached [ slow ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty
    let result = Aegis.capture config scope classify (fun () -> failwith "boom")

    Assert.True(Result.isError result)
    Assert.Equal(0, written.Value)
    gate.Set()

// ================================================================ prevention
//
// The tests below pin the explicit APIs so the same class of defect cannot
// return: every exception family has a declared classification, every exit
// of the final boundary is a named case, and persistence outcomes are values.

type private Classified =
    | AsCancellation
    | AsDefect
    | AsFault

let private classification (ex: exn) =
    if Aegis.isProgrammingDefect ex then AsDefect
    elif Aegis.isCancellation ex then AsCancellation
    else AsFault

[<Fact>]
let ``every exception family has a declared classification`` () =
    // Classification contract (aegis#13 AEGIS-QUAL-003). A change to any row
    // is a change to failure semantics and must be made here deliberately.
    use source = new Threading.CancellationTokenSource()
    source.Cancel()

    let table: (string * exn * Classified) list =
        [ "caller cancellation", OperationCanceledException(source.Token) :> exn, AsCancellation
          "bare cancellation", OperationCanceledException() :> exn, AsCancellation
          "task cancellation", TaskCanceledException() :> exn, AsCancellation
          "HttpClient timeout", httpClientTimeout () :> exn, AsFault
          "timeout", TimeoutException() :> exn, AsFault
          "network", Http.HttpRequestException "unreachable" :> exn, AsFault
          "io", IOException "disk" :> exn, AsFault
          "access", UnauthorizedAccessException() :> exn, AsFault
          "null reference", NullReferenceException() :> exn, AsDefect
          "invalid operation", InvalidOperationException() :> exn, AsDefect
          "argument", ArgumentException() :> exn, AsDefect ]

    for name, ex, expected in table do
        Assert.True((classification ex = expected), $"{name}: expected {expected}, got {classification ex}")

[<Fact>]
let ``withTimeouts gives a timeout the stable infrastructure code and delegates the rest`` () =
    let config = configWith Blocking []
    let scope = Aegis.scope config "Praxis.Remote.Fetch" Map.empty
    let classifier = Aegis.withTimeouts config classify

    let timeout = classifier scope (httpClientTimeout () :> exn)
    Assert.Equal(FaultCode "AEGIS.NETWORK.TIMEOUT", timeout.Code)
    Assert.Equal(InfrastructureFailure, timeout.Category)
    Assert.True(Catalog.lookup timeout.Code Catalog.builtIn |> Option.isSome)

    Assert.Equal(FaultCode "PRAXIS.REMOTE.CALL_FAILED", (classifier scope (Exception "other")).Code)

[<Fact>]
let ``captureReported surfaces a Required sink failure as an explicit outcome`` () =
    let config = configWith Blocking [ Sinks.noOp; Sinks.failing "audit" Sinks.Required ]
    let scope = Aegis.scope config "Praxis.Audit.Write" Map.empty

    match Aegis.captureReported config scope classify (fun () -> failwith "boom") with
    | Result.Error { Delivery = Delivery.RequiredSinkFailed report } ->
        Assert.True report.RequiredFailed
        Assert.Contains(Sinks.Failed("audit", Sinks.Required, "audit is unavailable"), report.Outcomes)
    | other -> failwith $"expected RequiredSinkFailed, got {other}"

[<Fact>]
let ``captureReported confirms persistence only when every Required sink wrote`` () =
    let collector = Sinks.Collector()
    // An Optional failure does not make the record unpersisted.
    let config = configWith Blocking [ collector.Sink Sinks.Required; Sinks.failing "console" Sinks.Optional ]
    let scope = Aegis.scope config "Praxis.Audit.Write" Map.empty

    match Aegis.captureReported config scope classify (fun () -> failwith "boom") with
    | Result.Error ({ Delivery = Delivery.Persisted _ } as captured) -> Assert.True(Delivery.isConfirmed captured.Delivery)
    | other -> failwith $"expected Persisted, got {other}"

[<Fact>]
let ``captureReported never claims a detached delivery was confirmed`` () =
    let config = configWith Detached [ Sinks.noOp ]
    let scope = Aegis.scope config "Praxis.Audit.Write" Map.empty

    match Aegis.captureReported config scope classify (fun () -> failwith "boom") with
    | Result.Error { Delivery = Delivery.NotAwaited as delivery } -> Assert.False(Delivery.isConfirmed delivery)
    | other -> failwith $"expected NotAwaited, got {other}"

[<Fact>]
let ``captureReportedAsync surfaces a Required sink failure too`` () =
    let config = configWith Blocking [ Sinks.failing "audit" Sinks.Required ]
    let scope = Aegis.scope config "Praxis.Audit.Write" Map.empty

    match
        Aegis.captureReportedAsync config scope classify (fun () -> async { return failwith "boom" })
        |> Async.RunSynchronously
    with
    | Result.Error { Delivery = Delivery.RequiredSinkFailed _ } -> ()
    | other -> failwith $"expected RequiredSinkFailed, got {other}"

[<Fact>]
let ``guardOutcome names every way the final boundary can end`` () =
    let collector = Sinks.Collector()
    let config = configWith Detached [ collector.Sink() ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty
    use source = new Threading.CancellationTokenSource()
    source.Cancel()

    Assert.Equal(Termination.Completed, Aegis.guardOutcome config scope classify ignore)
    Assert.Equal(Termination.Cancelled, Aegis.guardOutcome config scope classify (fun () -> raise (OperationCanceledException(source.Token))))

    // The final boundary awaits delivery even under Detached configuration.
    match Aegis.guardOutcome config scope classify (fun () -> raise (httpClientTimeout ())) with
    | Termination.Faulted { Delivery = Delivery.Persisted _ } -> Assert.Single collector.Events |> ignore
    | other -> failwith $"expected a persisted fault, got {other}"

[<Fact>]
let ``guardOutcome reports when the final record did not persist`` () =
    let config = configWith Blocking [ Sinks.failing "audit" Sinks.Required ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty

    match Aegis.guardOutcome config scope classify (fun () -> failwith "boom") with
    | Termination.Faulted { Delivery = Delivery.RequiredSinkFailed _ } -> ()
    | other -> failwith $"expected RequiredSinkFailed, got {other}"

[<Fact>]
let ``guardOutcomeAsync records a timeout and still re-raises a defect`` () =
    let collector = Sinks.Collector()
    let config = configWith Blocking [ collector.Sink() ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty

    match
        Aegis.guardOutcomeAsync config scope classify (fun () -> async { return raise (httpClientTimeout ()) })
        |> Async.RunSynchronously
    with
    | Termination.Faulted _ -> ()
    | other -> failwith $"expected Faulted, got {other}"

    Assert.Throws<InvalidOperationException>(fun () ->
        Aegis.guardOutcomeAsync config scope classify (fun () -> async { return raise (InvalidOperationException()) })
        |> Async.RunSynchronously
        |> ignore)
    |> ignore

    Assert.Equal(2, List.length collector.Events)

// ------------------------------------------------ detached delivery is observable

[<Fact>]
let ``flush awaits detached deliveries so a short-lived process does not lose them`` () =
    let written = ref 0

    let slow =
        { Sinks.noOp with
            Name = "slow"
            Write =
                fun _ ->
                    async {
                        do! Async.Sleep 100
                        Threading.Interlocked.Increment written |> ignore
                    } }

    let config = configWith Detached [ slow ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty
    Aegis.capture config scope classify (fun () -> failwith "boom") |> ignore

    match Aegis.flush (TimeSpan.FromSeconds 10.) with
    | FlushOutcome.Flushed _ -> Assert.Equal(1, written.Value)
    | FlushOutcome.TimedOut status -> failwith $"expected the flush to finish, got {status}"

[<Fact>]
let ``flush reports a timeout rather than claiming deliveries finished`` () =
    let gate = new Threading.ManualResetEventSlim(false)

    let stuck =
        { Sinks.noOp with
            Name = "stuck"
            Write = fun _ -> Async.AwaitWaitHandle gate.WaitHandle |> Async.Ignore }

    let config = configWith Detached [ stuck ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty
    Aegis.capture config scope classify (fun () -> failwith "boom") |> ignore

    try
        match Aegis.flush (TimeSpan.FromMilliseconds 50.) with
        | FlushOutcome.TimedOut status -> Assert.True(status.Pending >= 1)
        | FlushOutcome.Flushed status -> failwith $"a stuck delivery cannot have flushed: {status}"
    finally
        gate.Set()

[<Fact>]
let ``a Required sink failure in a detached delivery is counted, not lost`` () =
    let before = Aegis.detachedStatus ()
    let config = configWith Detached [ Sinks.failing "audit" Sinks.Required ]
    let scope = Aegis.scope config "Praxis.Main" Map.empty
    Aegis.capture config scope classify (fun () -> failwith "boom") |> ignore

    match Aegis.flush (TimeSpan.FromSeconds 10.) with
    | FlushOutcome.Flushed after -> Assert.True(after.RequiredFailures > before.RequiredFailures)
    | FlushOutcome.TimedOut status -> failwith $"expected the flush to finish, got {status}"

[<Fact>]
let ``forCommandLine awaits delivery before capture returns`` () =
    let collector = Sinks.Collector()
    let config = Aegis.forCommandLine (configWith Detached [ collector.Sink() ])
    let scope = Aegis.scope config "Praxis.Main" Map.empty

    Assert.Equal(Blocking, config.Persistence)
    Aegis.capture config scope classify (fun () -> failwith "boom") |> ignore
    Assert.Single collector.Events |> ignore
