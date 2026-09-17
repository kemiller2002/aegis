module Aegis.Tests.SinkTypes

open System
open System.IO
open System.Threading.Tasks
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 16, 0, 0, TimeSpan.Zero)

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

let private configWith sinks =
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
            n, n * 11L }

let private temp () =
    Path.Combine(Path.GetTempPath(), $"aegis-sink-{Guid.NewGuid():N}.jsonl")

// ------------------------------------------------------------------- file sink

[<Fact>]
let ``the file sink appends one event per line`` () =
    // Requirements: core 23; logging 2, 6, 30.
    let path = temp ()

    try
        let config = configWith [ Sinks.file path ]

        for n in 1..3 do
            Aegis.report config (FaultRecorded { fault with Id = FaultId $"01F{n}" }) |> ignore

        let lines = File.ReadAllLines path
        Assert.Equal(3, lines.Length)
        // Each line stands alone as readable JSON. Requirement: logging 30.
        for line in lines do
            match Store.index line with
            | Ok indexed -> Assert.Equal("FaultRecorded", indexed.EventType)
            | Result.Error e -> failwith $"line was not a readable event: {e}"
    finally
        if File.Exists path then File.Delete path

[<Fact>]
let ``the file sink appends rather than rewriting`` () =
    // Requirement: logging 6 -- append-oriented storage.
    let path = temp ()

    try
        let config = configWith [ Sinks.file path ]
        Aegis.report config (FaultRecorded fault) |> ignore
        let afterFirst = File.ReadAllLines path
        Aegis.report config (FaultRecorded fault) |> ignore
        let afterSecond = File.ReadAllLines path

        Assert.Equal(1, afterFirst.Length)
        Assert.Equal(2, afterSecond.Length)
        Assert.Equal(afterFirst.[0], afterSecond.[0])
    finally
        if File.Exists path then File.Delete path

[<Fact>]
let ``the file sink creates the directory it was given`` () =
    let directory = Path.Combine(Path.GetTempPath(), $"aegis-{Guid.NewGuid():N}")
    let path = Path.Combine(directory, "events.jsonl")

    try
        Aegis.report (configWith [ Sinks.file path ]) (FaultRecorded fault) |> ignore
        Assert.True(File.Exists path)
    finally
        if Directory.Exists directory then Directory.Delete(directory, true)

[<Fact>]
let ``the file sink tolerates concurrent writes`` () =
    // Requirement: logging 34 -- a file handle is not concurrently appendable,
    // so the sink must serialize its own writes.
    let path = temp ()

    try
        let sink = Sinks.file path
        Parallel.For(0, 100, fun n -> sink.Write $"{{\"eventId\":\"E{n}\"}}" |> Async.RunSynchronously) |> ignore
        Assert.Equal(100, (File.ReadAllLines path).Length)
    finally
        if File.Exists path then File.Delete path

[<Fact>]
let ``the file sink batches without losing events`` () =
    // Requirement: logging 19.
    let path = temp ()

    try
        let config = configWith [ Sinks.file path ]
        let events = [ for n in 1..5 -> FaultRecorded { fault with Id = FaultId $"01F{n}" } ]
        Aegis.reportBatch config events |> ignore
        Assert.Equal(5, (File.ReadAllLines path).Length)
    finally
        if File.Exists path then File.Delete path

[<Fact>]
let ``the file sink redacts like any other sink`` () =
    // Requirement: logging 21 -- a new sink must not become a leak.
    let path = temp ()

    try
        let config = configWith [ Sinks.file path ]
        let leaky = { fault with Context = Map [ "github_token", Public "ghp_leaked" ] }
        Aegis.report config (FaultRecorded leaky) |> ignore
        Assert.DoesNotContain("ghp_leaked", File.ReadAllText path)
    finally
        if File.Exists path then File.Delete path

[<Fact>]
let ``a file sink that cannot write is contained like any other failure`` () =
    // Requirements: core 25; logging 16.
    let collector = Sinks.Collector()
    // A directory path is not a writable file.
    let config = configWith [ Sinks.file (Path.GetTempPath()); collector.Sink() ]
    let report = Aegis.report config (FaultRecorded fault)

    Assert.True report.FallbackUsed
    // The healthy sink still received it. Requirement: logging 15.
    Assert.Single collector.Events |> ignore

// --------------------------------------------------------- console and no-op

[<Fact>]
let ``the console sink writes the event to standard output`` () =
    // Requirements: core 23; logging 2.
    let original = Console.Out
    use captured = new StringWriter()

    try
        Console.SetOut captured
        Aegis.report (configWith [ Sinks.console ]) (FaultRecorded fault) |> ignore
    finally
        Console.SetOut original

    Assert.Contains("CHRONA.GITHUB.LOAD_FAILED", captured.ToString())

[<Fact>]
let ``the standard error sink keeps diagnostics off normal output`` () =
    let originalOut = Console.Out
    let originalError = Console.Error
    use outWriter = new StringWriter()
    use errorWriter = new StringWriter()

    try
        Console.SetOut outWriter
        Console.SetError errorWriter
        Aegis.report (configWith [ Sinks.standardError ]) (FaultRecorded fault) |> ignore
    finally
        Console.SetOut originalOut
        Console.SetError originalError

    Assert.Contains("CHRONA.GITHUB.LOAD_FAILED", errorWriter.ToString())
    Assert.Equal("", outWriter.ToString())

[<Fact>]
let ``the no-op sink accepts everything and records nothing`` () =
    // Requirement: core 23.
    let report = Aegis.report (configWith [ Sinks.noOp ]) (FaultRecorded fault)
    Assert.All(report.Outcomes, fun o -> Assert.False(Sinks.isFailure o))
    Assert.False report.FallbackUsed

[<Fact>]
let ``every named sink type is constructible and reports its own name`` () =
    // Requirements: core 23; logging 2 -- the enumerated sink types exist.
    let names =
        [ Sinks.console; Sinks.standardError; Sinks.noOp; Sinks.file (temp ()); Sinks.Collector().Sink() ]
        |> List.map (fun s -> s.Name)

    Assert.Equal<string list>([ "console"; "stderr"; "no-op"; "file"; "collector" ], names)

// ------------------------------------------------------- top-level boundary

let private classify (scope: Scope) (ex: exn) =
    { fault with
        Operation = scope.Operation
        CorrelationId = scope.CorrelationId
        TechnicalDetails = Some ex.Message }

[<Fact>]
let ``the top-level guard records what reaches it`` () =
    // Requirement: additional 22.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.CommandLoop" Map.empty

    Aegis.guard config scope classify (fun () -> failwith "nothing else caught this")

    Assert.Single collector.Events |> ignore
    Assert.Contains("nothing else caught this", List.head collector.Events)

[<Fact>]
let ``the top-level guard does not let an ordinary failure kill the process`` () =
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.CommandLoop" Map.empty

    // No exception escapes.
    Aegis.guard config scope classify (fun () -> failwith "boom")
    Assert.Single collector.Events |> ignore

[<Fact>]
let ``the top-level guard records a programming defect and still fails loudly`` () =
    // Requirement: core 19 -- swallowing a defect here would hide corruption.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.CommandLoop" Map.empty

    Assert.Throws<InvalidOperationException>(fun () ->
        Aegis.guard config scope classify (fun () -> raise (InvalidOperationException "impossible case")))
    |> ignore

    // Recorded before re-raising, so the defect is not lost.
    Assert.Single collector.Events |> ignore

[<Fact>]
let ``the top-level guard treats cancellation as shutdown, not a fault`` () =
    // Requirement: core 29.
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.CommandLoop" Map.empty

    Aegis.guard config scope classify (fun () -> raise (OperationCanceledException()))
    Assert.Empty collector.Events

[<Fact>]
let ``a successful top-level operation records nothing`` () =
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.CommandLoop" Map.empty

    let ran = ref false
    Aegis.guard config scope classify (fun () -> ran.Value <- true)

    Assert.True ran.Value
    Assert.Empty collector.Events

[<Fact>]
let ``the async top-level guard behaves the same way`` () =
    let collector = Sinks.Collector()
    let config = configWith [ collector.Sink() ]
    let scope = Aegis.scope config "Chrona.IntegrationProcessor" Map.empty

    Aegis.guardAsync config scope classify (fun () -> async { return failwith "async boom" })
    |> Async.RunSynchronously

    Assert.Single collector.Events |> ignore
    Assert.Contains("async boom", List.head collector.Events)
