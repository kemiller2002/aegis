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

    /// Cancellation is not a failure: it may mean the user navigated away or a
    /// newer request superseded this one. Requirement: core 29.
    let isCancellation (ex: exn) =
        match ex with
        | :? OperationCanceledException -> true
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
    /// application's primary operation. Requirement: logging 18.
    let reportDetached config (ev: AegisEvent) =
        reportAsync config ev |> Async.Ignore |> Async.Start

    /// Record a group of events, using each sink's batch path where it has
    /// one. Requirement: logging 19.
    let reportBatch config (events: AegisEvent list) =
        let ids = events |> List.map (fun _ -> newId config EventId)
        Sinks.deliverBatchAsync config.Fallback config.Rules ids config.Sinks events
        |> Async.RunSynchronously

    /// Report according to the configured persistence mode. This is what the
    /// capture path uses, so the default costs the caller nothing.
    let private emit config (ev: AegisEvent) =
        match config.Persistence with
        | Detached -> reportDetached config ev
        | Blocking -> report config ev |> ignore

    /// Guard a boundary. On success the value is returned; on an unexpected
    /// failure the fault is recorded and returned, never swallowed. Programming
    /// defects and cancellation are deliberately not converted into faults.
    /// Requirements: core 5, 6, 7, 19, 29.
    let capture config scope classify (operation: unit -> 'T) : Guarded<'T> =
        try
            Ok(operation ())
        with ex ->
            if isProgrammingDefect ex then reraise ()
            elif isCancellation ex then reraise ()
            else
                let fault = classify scope ex
                emit config (FaultRecorded fault)
                Result.Error fault

    /// Async form. Requirement: core 5.
    let captureAsync config scope classify (operation: unit -> Async<'T>) : Async<Guarded<'T>> =
        async {
            try
                let! value = operation ()
                return Ok value
            with ex ->
                if isProgrammingDefect ex || isCancellation ex then
                    return rethrow ex
                else
                    let fault = classify scope ex
                    emit config (FaultRecorded fault)
                    return Result.Error fault
        }

    /// Suppression is permitted only under a declared policy, and is itself
    /// recorded. Requirement: core 7.
    let suppress config fault reason =
        report config (FaultSuppressed(fault, reason))
