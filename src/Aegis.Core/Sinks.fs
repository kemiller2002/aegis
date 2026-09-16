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
          /// Writes one serialized event. Raising is permitted: the runtime
          /// contains the failure rather than trusting sinks to behave.
          Write: string -> unit }

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

    let private attempt (payload: string) (sink: Sink) =
        try
            sink.Write payload
            Written sink.Name
        with ex ->
            Failed(sink.Name, sink.Level, ex.Message)

    /// Deliver one event to every sink. Each sink is attempted independently.
    /// If any sink fails, a minimal sink-failure event is offered to the
    /// fallback exactly once -- never through the failing sinks, so no
    /// recursion is possible. Requirements: logging 15, 16; core 24, 25.
    let deliver (fallback: string -> unit) (rules: Redaction.Rule list) (eventId: EventId) (sinks: Sink list) (ev: AegisEvent) =
        let payload = Serialization.event rules eventId ev
        let outcomes = sinks |> List.map (attempt payload)
        let failures = outcomes |> List.filter isFailure

        let fallbackUsed =
            match failures with
            | [] -> false
            | _ ->
                // The fallback is a plain function, not a sink, and is invoked
                // at most once per delivery: the hard re-entry guard.
                let summary =
                    failures
                    |> List.map (function
                        | Failed (name, _, message) -> $"{name}: {message}"
                        | Written name -> name)
                    |> String.concat "; "

                try
                    fallback $"aegis sink failure while writing {Serialization.eventTypeName ev}: {summary}"
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
              Write =
                fun payload ->
                    events.Enqueue payload
                    this.Trim() }

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
          Write = fun _ -> failwith $"{name} is unavailable" }
