namespace Aegis

open System

/// Sinks receive already-redacted events. Failure of one sink never prevents
/// the others from receiving the event, and a sink failure can never drive
/// Aegis into recursion.
/// Requirements: core 23, 24, 25; additional 48, 49, 50; logging 2, 14, 15, 16.
module Sinks =

    /// Requirement: additional 50. A required sink's failure may change the
    /// application's operating mode; an optional sink's must not.
    type Level =
        | Required
        | Preferred
        | Optional

    /// Requirement: additional 48. Aegis must not assume every sink behaves alike.
    type Capability =
        | SupportsBatch
        | SupportsQuery
        | SupportsDurableWrite
        | SupportsRetention
        | SupportsOfflineQueue
        | SupportsIdempotency

    type Sink =
        { Name: string
          Level: Level
          Capabilities: Capability list
          /// Writes one serialized event. Asynchronous so the reporting path
          /// adds minimal latency and a slow remote sink never blocks the
          /// application's primary operation. Raising or failing the async is
          /// permitted: the runtime contains the failure rather than trusting
          /// sinks to behave. Requirements: logging 17, 18.
          Write: string -> Async<unit>
          /// Batch write for a sink advertising SupportsBatch. Batching must
          /// not lose identity or ordering, so the list is delivered in order.
          /// Requirement: logging 19.
          WriteBatch: (string list -> Async<unit>) option }

    /// Per-sink result, so suppression is never silent. Requirement: core 7.
    type Outcome =
        | Written of sink: string
        | Failed of sink: string * level: Level * message: string

    let isFailure =
        function
        | Written _ -> false
        | Failed _ -> true

    /// A delivery report. `FallbackUsed` records that the last-resort path was
    /// taken because a sink failed. Requirement: core 25, logging 16.
    type Report =
        { Outcomes: Outcome list
          FallbackUsed: bool
          RequiredFailed: bool }

    /// Build the delivery report and take the last-resort path at most once
    /// per delivery: the hard re-entry guard. Requirements: core 25; logging 16.
    let private report (fallback: string -> unit) (description: string) (outcomes: Outcome list) =
        let failures = outcomes |> List.filter isFailure

        let fallbackUsed =
            match failures with
            | [] -> false
            | _ ->
                let summary =
                    failures
                    |> List.map (function
                        | Failed (name, _, message) -> $"{name}: {message}"
                        | Written name -> name)
                    |> String.concat "; "

                try
                    fallback $"aegis sink failure while writing {description}: {summary}"
                    true
                with _ ->
                    // Even the fallback may fail. There is nowhere further to
                    // go, and Aegis must not crash the application for it.
                    true

        { Outcomes = outcomes
          FallbackUsed = fallbackUsed
          RequiredFailed =
            failures
            |> List.exists (function
                | Failed (_, Required, _) -> true
                | _ -> false) }

    let private attempt (payload: string) (sink: Sink) =
        async {
            try
                do! sink.Write payload
                return Written sink.Name
            with ex ->
                return Failed(sink.Name, sink.Level, ex.Message)
        }

    let private attemptBatch (payloads: string list) (sink: Sink) =
        async {
            try
                match sink.WriteBatch with
                | Some writeBatch when sink.Capabilities |> List.contains SupportsBatch ->
                    do! writeBatch payloads
                | _ ->
                    // A sink without batch support still receives every event,
                    // in order. Requirement: logging 19.
                    for payload in payloads do
                        do! sink.Write payload

                return Written sink.Name
            with ex ->
                return Failed(sink.Name, sink.Level, ex.Message)
        }

    /// Deliver one event to every sink. Each sink is attempted
    /// independently. If any sink fails, a minimal sink-failure summary is
    /// offered to the fallback exactly once -- never through the failing
    /// sinks, so no recursion is possible.
    /// Requirements: logging 15, 16, 18; core 24, 25.
    let deliverAsync (fallback: string -> unit) (rules: Redaction.Rule list) (eventId: EventId) (sinks: Sink list) (ev: AegisEvent) =
        async {
            let payload = Serialization.event rules eventId ev
            // Sinks are attempted in parallel: one slow sink must not delay
            // the others. Requirement: logging 15, 18.
            let! outcomes = sinks |> List.map (attempt payload) |> Async.Parallel
            return report fallback (Serialization.eventTypeName ev) (List.ofArray outcomes)
        }

    /// Deliver several events, using each sink's batch path where it has one.
    /// Requirement: logging 19.
    let deliverBatchAsync (fallback: string -> unit) (rules: Redaction.Rule list) (ids: EventId list) (sinks: Sink list) (events: AegisEvent list) =
        async {
            let payloads = List.zip ids events |> List.map (fun (id, ev) -> Serialization.event rules id ev)
            let! outcomes = sinks |> List.map (attemptBatch payloads) |> Async.Parallel
            return report fallback $"batch of {List.length events}" (List.ofArray outcomes)
        }

    /// In-memory sink for tests and for a bounded local history.
    /// Requirements: core 22, 27; logging 41.
    type Collector(?capacity: int) =
        let limit = defaultArg capacity 50
        let events = System.Collections.Concurrent.ConcurrentQueue<string>()

        /// Bounded: history must not grow without limit. Requirement: core 22.
        member private _.Trim() =
            while events.Count > limit do
                events.TryDequeue() |> ignore

        member this.Sink(?level: Level) =
            { Name = "collector"
              Level = defaultArg level Optional
              Capabilities = [ SupportsQuery ]
              WriteBatch = None
              Write =
                fun payload ->
                    async {
                        events.Enqueue payload
                        this.Trim()
                    } }

        /// Immutable snapshot. Tests assert against this rather than console output.
        member _.Events = events |> Seq.toList

        member this.Codes =
            this.Events
            |> List.choose (fun e ->
                let marker = "\"code\":\""
                match e.IndexOf marker with
                | -1 -> None
                | i ->
                    let start = i + marker.Length
                    Some(e.Substring(start, e.IndexOf('"', start) - start)))

    /// A sink that always throws, for verifying containment.
    let failing name level =
        { Name = name
          Level = level
          Capabilities = []
          WriteBatch = None
          Write = fun _ -> async { return failwith $"{name} is unavailable" } }

    /// Per-sink health derived from observed outcomes rather than hidden
    /// counters, so it is reproducible and inspectable.
    /// Requirement: logging 38.
    type State =
        | Available
        | SinkDegraded
        | SinkUnavailable

    type Health =
        { Sink: string
          Level: Level
          State: State
          Writes: int
          Failures: int
          LastSuccess: DateTimeOffset option
          LastFailure: (DateTimeOffset * string) option }

    let private fold (health: Health) (at: DateTimeOffset, outcome: Outcome) =
        match outcome with
        | Written _ ->
            { health with
                Writes = health.Writes + 1
                LastSuccess = Some at
                State = Available }
        | Failed (_, _, message) ->
            let failures = health.Failures + 1

            { health with
                Failures = failures
                LastFailure = Some(at, message)
                // One failure is degradation; a failure with no success since
                // is unavailability.
                State = if health.LastSuccess.IsNone then SinkUnavailable else SinkDegraded }

    /// Observed history of (time, outcome) pairs to per-sink health.
    let observe (observations: (DateTimeOffset * Outcome) list) =
        observations
        |> List.fold
            (fun acc (at, outcome) ->
                let name, level =
                    match outcome with
                    | Written name -> name, Optional
                    | Failed (name, level, _) -> name, level

                let current =
                    acc
                    |> Map.tryFind name
                    |> Option.defaultValue
                        { Sink = name
                          Level = level
                          State = Available
                          Writes = 0
                          Failures = 0
                          LastSuccess = None
                          LastFailure = None }

                Map.add name (fold current (at, outcome)) acc)
            Map.empty

    /// Flatten reports into observations, for callers that keep a report log.
    let observationsOf (at: DateTimeOffset) (reports: Report list) =
        reports |> List.collect (fun r -> r.Outcomes |> List.map (fun o -> at, o))
