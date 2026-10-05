namespace Aegis

open System

/// Whether reporting waits for persistence.
/// Requirements: logging 17, 18.
type PersistenceMode =
    /// The default. Reporting starts delivery and returns, so a slow remote
    /// sink never blocks the application's primary operation.
    | Detached
    /// Await delivery before returning. For the case logging 17 carves out,
    /// where audit persistence is itself a business or compliance
    /// requirement, and for deterministic tests.
    | Blocking

/// Configuration is supplied once, not threaded through application methods.
/// Requirements: core 26; logging 39.
type AegisConfig =
    { Application: string
      Version: string option
      Sinks: Sinks.Sink list
      Rules: Redaction.Rule list
      /// Last-resort path when a sink fails. Requirement: core 25.
      Fallback: string -> unit
      /// Whether reporting blocks on persistence. Requirements: logging 17, 18.
      Persistence: PersistenceMode
      /// Injected so behaviour is deterministic under test. Requirement: core 27.
      Now: unit -> DateTimeOffset
      Random: unit -> int64 * int64 }

/// Ambient diagnostic context for an operation, established once by a scope
/// and inherited by every fault raised inside it.
/// Requirements: core 13, 14; additional 1.
type Scope =
    { Operation: string
      CorrelationId: CorrelationId
      Context: Map<string, ContextValue> }

/// The result of guarding a boundary. A caller cannot ignore a failure by
/// accident: the fault is in the type. Requirement: core 7.
type Guarded<'T> = Result<'T, Fault>

/// What became of a fault's own record. Persistence failure is a failure in
/// its own right and must be visible to the caller, not only to the
/// fallback. Requirements: core 7, 25; additional 50; logging 17.
[<RequireQualifiedAccess>]
type Delivery =
    /// Delivery was awaited and every Required sink wrote the event.
    /// Optional or Preferred sinks may still have failed; the report says.
    | Persisted of Sinks.Report
    /// Delivery was awaited and at least one Required sink did not write the
    /// event. The fault was raised, but its compliance record does not exist.
    | RequiredSinkFailed of Sinks.Report
    /// Detached persistence: delivery was started and not awaited, so its
    /// outcome is unknown here. `Aegis.flush` awaits it and
    /// `Aegis.detachedStatus` counts its failures.
    | NotAwaited

module Delivery =

    let ofReport (report: Sinks.Report) =
        if report.RequiredFailed then Delivery.RequiredSinkFailed report else Delivery.Persisted report

    /// Only an awaited delivery with no Required failure is confirmed.
    let isConfirmed =
        function
        | Delivery.Persisted _ -> true
        | Delivery.RequiredSinkFailed _
        | Delivery.NotAwaited -> false

/// A fault together with what happened to its record.
type Captured = { Fault: Fault; Delivery: Delivery }

/// How a top-level boundary ended. Every exit is a named case, so nothing
/// that reaches the final boundary can disappear without trace.
/// Requirements: additional 22; core 7, 29.
[<RequireQualifiedAccess>]
type Termination =
    | Completed
    /// The caller's own cancellation (core 29). Not a fault, and not
    /// recorded, but explicit. A timeout is never classified here.
    | Cancelled
    | Faulted of Captured

/// Process-wide account of detached deliveries, so fire-and-forget loss is
/// observable rather than silent. Requirements: core 7; logging 17, 18.
type DetachedStatus =
    { /// Deliveries started and not yet finished.
      Pending: int
      /// Deliveries finished since process start.
      Completed: int64
      /// Finished deliveries in which a Required sink failed.
      RequiredFailures: int64
      /// Deliveries that ended in an exception rather than a report.
      Faulted: int64 }

/// The result of waiting for detached deliveries.
[<RequireQualifiedAccess>]
type FlushOutcome =
    /// Every delivery in flight when the flush began has finished.
    | Flushed of DetachedStatus
    /// The timeout passed first; `Pending` deliveries may still be lost.
    | TimedOut of DetachedStatus

/// Tracks detached deliveries. This is the one piece of mutable process
/// state in the capture path; it exists only because fire-and-forget work
/// otherwise has no handle by which its loss could be observed.
module internal DetachedDeliveries =
    open System.Collections.Concurrent
    open System.Threading
    open System.Threading.Tasks

    let private inFlight = ConcurrentDictionary<int64, Task>()
    let mutable private nextKey = 0L
    let mutable private completed = 0L
    let mutable private requiredFailures = 0L
    let mutable private faulted = 0L

    let track (delivery: Async<Sinks.Report>) =
        let key = Interlocked.Increment(&nextKey)
        let finished = TaskCompletionSource<unit>(TaskCreationOptions.RunContinuationsAsynchronously)
        // Registered before delivery starts, so a flush can never miss it.
        inFlight.[key] <- finished.Task

        Async.Start(
            async {
                try
                    try
                        let! report = delivery

                        if report.RequiredFailed then
                            Interlocked.Increment(&requiredFailures) |> ignore
                    with _ ->
                        // Counted, so the loss is observable.
                        Interlocked.Increment(&faulted) |> ignore
                finally
                    Interlocked.Increment(&completed) |> ignore
                    inFlight.TryRemove key |> ignore
                    finished.TrySetResult() |> ignore
            }
        )

    let status () =
        { Pending = inFlight.Count
          Completed = Interlocked.Read(&completed)
          RequiredFailures = Interlocked.Read(&requiredFailures)
          Faulted = Interlocked.Read(&faulted) }

    let flush (timeout: TimeSpan) =
        let pending = inFlight.Values |> Seq.toArray

        let finished =
            Array.isEmpty pending
            || (try
                    Task.WaitAll(pending, timeout)
                with :? AggregateException ->
                    // Observed failures are already counted.
                    true)

        if finished then FlushOutcome.Flushed(status ()) else FlushOutcome.TimedOut(status ())

module Aegis =

    let private newId config ctor =
        ctor (Id.generate (config.Now()) (config.Random()))

    let configure application version sinks =
        { Application = application
          Version = version
          Sinks = sinks
          Rules = Redaction.defaultRules
          Fallback = ignore
          Persistence = Detached
          Now = fun () -> DateTimeOffset.UtcNow
          Random =
            let rng = Random.Shared
            fun () -> rng.NextInt64(), rng.NextInt64() }

    /// Requirement: additional 1. Scope context is inherited unless a fault
    /// explicitly overrides a key.
    let scope config operation context =
        { Operation = operation
          CorrelationId = newId config CorrelationId
          Context = context }

    /// A nested scope keeps the parent's correlation id, so one user action is
    /// traceable across every layer. Requirement: core 14.
    let nest (parent: Scope) operation context =
        { Operation = operation
          CorrelationId = parent.CorrelationId
          Context = context |> Map.fold (fun acc k v -> Map.add k v acc) parent.Context }

    /// Rethrows preserving the original stack trace, typed to flow in any
    /// position. Used where `reraise` is unavailable, such as inside an async
    /// computation expression. Requirement: core 17.
    let private rethrow (ex: exn) : 'a =
        Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw()
        failwith "unreachable: Throw always raises"

    let rec private detail (ex: exn) =
        { ExceptionType = ex.GetType().FullName
          Message = ex.Message
          StackTrace = ex.StackTrace |> Option.ofObj
          Inner = ex.InnerException |> Option.ofObj |> Option.map detail }

    /// Programming defects must be distinguishable and must fail loudly rather
    /// than becoming a harmless warning. Requirement: core 19.
    let isProgrammingDefect (ex: exn) =
        match ex with
        | :? NullReferenceException
        | :? IndexOutOfRangeException
        | :? InvalidOperationException
        | :? ArgumentException -> true
        | _ -> false

    /// A timeout is an infrastructure failure, not a cancellation, even when
    /// it arrives dressed as one: HttpClient reports its own Timeout as a
    /// TaskCanceledException whose inner exception is a TimeoutException.
    /// Requirements: core 29; aegis#13 AEGIS-QUAL-003.
    let rec isTimeout (ex: exn) =
        match ex with
        | :? TimeoutException -> true
        | :? OperationCanceledException as cancelled ->
            cancelled.InnerException |> Option.ofObj |> Option.exists isTimeout
        | _ -> false

    /// Cancellation is not a failure: it may mean the user navigated away or a
    /// newer request superseded this one. A timeout is excluded, because
    /// nobody asked for it: it is a failure and must reach the fault model.
    /// Requirement: core 29.
    let isCancellation (ex: exn) =
        match ex with
        | :? OperationCanceledException -> not (isTimeout ex)
        | _ -> false

    /// Build a fault from a classified exception at a boundary.
    let faultOf config (scope: Scope) code category severity impact persistence recovery userMessage (ex: exn) =
        { Id = newId config FaultId
          CorrelationId = scope.CorrelationId
          Timestamp = config.Now()
          Application = config.Application
          ApplicationVersion = config.Version
          Operation = scope.Operation
          Category = category
          Code = code
          Severity = severity
          Impact = impact
          Domain = IntegrationDomain
          Radius = OneOperation
          Retention = DiagnosticOnly
          Persistence = persistence
          Owner = None
          Dependencies = [ config.Application ]
          UserMessage = userMessage
          TechnicalDetails = Some ex.Message
          Context = scope.Context
          Recovery = recovery
          Diagnostics = noDiagnostics
          Cause = Some(CausedByException(detail ex)) }

    /// Record an event through the configured sinks, awaiting delivery.
    /// Redaction happens inside serialization, so no sink ever sees an
    /// unredacted payload. Requirements: logging 21; core 24, 25.
    let reportAsync config (ev: AegisEvent) =
        Sinks.deliverAsync config.Fallback config.Rules (newId config EventId) config.Sinks ev

    /// Awaits delivery and returns the outcome. Used where the result matters:
    /// audit-required persistence, and deterministic tests.
    let report config (ev: AegisEvent) =
        reportAsync config ev |> Async.RunSynchronously

    /// Starts delivery and returns immediately, adding minimal latency to the
    /// application's primary operation. The delivery is tracked, so `flush`
    /// can await it and `detachedStatus` can count its failures.
    /// Requirement: logging 18.
    let reportDetached config (ev: AegisEvent) =
        DetachedDeliveries.track (reportAsync config ev)

    /// Counts of detached deliveries: pending, completed, and those in which
    /// a Required sink failed. Requirement: core 7.
    let detachedStatus () = DetachedDeliveries.status ()

    /// Await every detached delivery in flight, up to `timeout`. A
    /// short-lived process calls this before exiting so detached fault
    /// records are not lost; the outcome says whether any may have been.
    /// Requirements: logging 17, 18; additional 21.
    let flush (timeout: TimeSpan) = DetachedDeliveries.flush timeout

    /// Configuration for a short-lived process such as a command-line tool:
    /// delivery is awaited before `capture` returns, and a sink failure is
    /// written to standard error rather than discarded. The default remains
    /// Detached for long-running hosts; this is an explicit opt-in.
    /// Requirements: logging 17; core 25.
    let forCommandLine (config: AegisConfig) =
        { config with
            Persistence = Blocking
            Fallback = fun message -> Console.Error.WriteLine message }

    /// Record a group of events, using each sink's batch path where it has
    /// one. Requirement: logging 19.
    let reportBatch config (events: AegisEvent list) =
        let ids = events |> List.map (fun _ -> newId config EventId)
        Sinks.deliverBatchAsync config.Fallback config.Rules ids config.Sinks events
        |> Async.RunSynchronously

    /// Report according to the configured persistence mode, returning what
    /// is known about the record's delivery.
    let private emitAsync config (ev: AegisEvent) =
        match config.Persistence with
        | Detached ->
            reportDetached config ev
            async.Return Delivery.NotAwaited
        | Blocking ->
            async {
                let! report = reportAsync config ev
                return Delivery.ofReport report
            }

    /// Classify, record and describe a failure that reached a boundary.
    let private recordFailure config scope classify (ex: exn) =
        async {
            let fault = classify scope ex
            let! delivery = emitAsync config (FaultRecorded fault)
            return { Fault = fault; Delivery = delivery }
        }

    /// Guard a boundary and report what happened to the fault's record as
    /// well as the fault itself. Use this where persistence matters: with a
    /// Required sink, `RequiredSinkFailed` tells the caller the fault was
    /// raised but its record does not exist. Programming defects and caller
    /// cancellation are re-raised, exactly as in `capture`.
    /// Requirements: core 5, 6, 7, 19, 29; additional 50.
    let captureReported config scope classify (operation: unit -> 'T) : Result<'T, Captured> =
        try
            Ok(operation ())
        with ex ->
            if isProgrammingDefect ex then reraise ()
            elif isCancellation ex then reraise ()
            else Result.Error(recordFailure config scope classify ex |> Async.RunSynchronously)

    /// Async form of `captureReported`.
    let captureReportedAsync config scope classify (operation: unit -> Async<'T>) : Async<Result<'T, Captured>> =
        async {
            try
                let! value = operation ()
                return Ok value
            with ex ->
                if isProgrammingDefect ex || isCancellation ex then
                    return rethrow ex
                else
                    let! captured = recordFailure config scope classify ex
                    return Result.Error captured
        }

    /// Guard a boundary. On success the value is returned; on an unexpected
    /// failure the fault is recorded and returned, never swallowed. Programming
    /// defects and caller cancellation are deliberately not converted into
    /// faults; a timeout is a failure, not a cancellation.
    ///
    /// The fault's delivery outcome is not part of this result. Where a
    /// Required sink must hold the record, use `captureReported`.
    /// Requirements: core 5, 6, 7, 19, 29.
    let capture config scope classify (operation: unit -> 'T) : Guarded<'T> =
        captureReported config scope classify operation |> Result.mapError (fun captured -> captured.Fault)

    /// Async form. Requirement: core 5.
    let captureAsync config scope classify (operation: unit -> Async<'T>) : Async<Guarded<'T>> =
        async {
            let! result = captureReportedAsync config scope classify operation
            return result |> Result.mapError (fun captured -> captured.Fault)
        }

    /// The final boundary, reporting how it ended. Every exit is explicit:
    /// `Completed`, `Cancelled` (the caller's own cancellation only -- a
    /// timeout is `Faulted`), or `Faulted` with the fault and whether its
    /// record was persisted. Delivery is always awaited here, because the
    /// process may be about to end. A programming defect is recorded and
    /// then re-raised (core 19).
    /// Requirements: additional 22; core 7, 19, 29.
    let guardOutcome config scope classify (operation: unit -> unit) : Termination =
        try
            operation ()
            Termination.Completed
        with ex ->
            if isCancellation ex then
                Termination.Cancelled
            else
                let fault = classify scope ex
                let report = report config (FaultRecorded fault)

                if isProgrammingDefect ex then reraise ()

                Termination.Faulted
                    { Fault = fault
                      Delivery = Delivery.ofReport report }

    /// Async form of `guardOutcome`.
    let guardOutcomeAsync config scope classify (operation: unit -> Async<unit>) : Async<Termination> =
        async {
            try
                do! operation ()
                return Termination.Completed
            with ex ->
                if isCancellation ex then
                    return Termination.Cancelled
                else
                    let fault = classify scope ex
                    let! report = reportAsync config (FaultRecorded fault)

                    if isProgrammingDefect ex then
                        return rethrow ex
                    else
                        return
                            Termination.Faulted
                                { Fault = fault
                                  Delivery = Delivery.ofReport report }
        }

    /// The final boundary around an application's top-level execution
    /// surface: a command loop, a startup entry point, an integration
    /// processor, a UI event dispatcher.
    ///
    /// This is the last line of defence, not the primary error-handling
    /// strategy, so it records whatever reaches it rather than letting the
    /// process die unexplained. A programming defect is still re-raised after
    /// being recorded, because core 19 requires defects to fail loudly and
    /// swallowing one here would hide a corrupt state. The caller's own
    /// cancellation is neither recorded nor re-raised: at the top level it
    /// means the application is shutting down or the user navigated away. A
    /// timeout is not cancellation and is recorded like any other failure.
    ///
    /// `guard` returns unit for compatibility. `guardOutcome` returns the
    /// same decision as a value, including whether the record persisted.
    /// Requirements: additional 22; core 7, 19, 29.
    let guard config scope classify (operation: unit -> unit) =
        guardOutcome config scope classify operation |> ignore

    /// Async form of the top-level boundary. Requirement: additional 22.
    let guardAsync config scope classify (operation: unit -> Async<unit>) =
        async {
            let! _ = guardOutcomeAsync config scope classify operation
            return ()
        }

    /// A classifier that gives every timeout the stable infrastructure code
    /// `AEGIS.NETWORK.TIMEOUT` and delegates everything else. Compose it
    /// over an application classifier when the application has no timeout
    /// code of its own. Requirement: aegis#13 AEGIS-QUAL-003.
    let withTimeouts config (classify: Scope -> exn -> Fault) (scope: Scope) (ex: exn) =
        if isTimeout ex then
            { faultOf
                config
                scope
                (FaultCode "AEGIS.NETWORK.TIMEOUT")
                InfrastructureFailure
                FaultSeverity.Warning
                OperationOnly
                Transient
                (Retry(3, Exponential(TimeSpan.FromSeconds 1.)))
                "The operation timed out."
                ex with
                Domain = EnvironmentDomain }
        else
            classify scope ex

    /// Suppression is permitted only under a declared policy, and is itself
    /// recorded. Requirement: core 7.
    let suppress config fault reason =
        report config (FaultSuppressed(fault, reason))
