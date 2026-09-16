namespace Aegis

open System
open System.Text.Json

/// The durable store contract and a query model that does not depend on any
/// storage provider. Concrete adapters live outside this assembly.
/// Requirements: logging 3, 4, 27, 28, 36, 37.
module Store =

    /// Storage outcomes are explicit. A conflict is abnormal rather than a
    /// cue to overwrite: event records are immutable and uniquely named.
    /// Requirement: logging 36.
    type Failure =
        | Conflict of path: string
        | Unavailable of reason: string
        | Rejected of reason: string
        /// A storage response that could not be understood. Requirement: logging 40.
        | Malformed of detail: string

    /// Provider-independent filters. Requirement: logging 27.
    type Query =
        { EventId: EventId option
          FaultId: FaultId option
          CorrelationId: CorrelationId option
          Application: string option
          Operation: string option
          Code: FaultCode option
          Severity: FaultSeverity option
          EventType: string option
          From: DateTimeOffset option
          Until: DateTimeOffset option }

    /// Matches everything; narrow it with record update syntax.
    let anyEvent =
        { EventId = None
          FaultId = None
          CorrelationId = None
          Application = None
          Operation = None
          Code = None
          Severity = None
          EventType = None
          From = None
          Until = None }

    /// The structured fields a stored event can be searched by, recovered from
    /// its payload. Searching uses these rather than text search over
    /// human-readable messages. Requirements: additional 41; logging 10, 27, 29.
    type Indexed =
        { EventId: EventId
          EventType: string
          FaultId: FaultId option
          CorrelationId: CorrelationId option
          Application: string option
          Operation: string option
          Code: FaultCode option
          Severity: string option
          Timestamp: DateTimeOffset option }

    let private tryString (root: JsonElement) (name: string) =
        match root.TryGetProperty name with
        | true, value when value.ValueKind = JsonValueKind.String -> Some(value.GetString())
        | _ -> None

    /// Parse the indexable fields out of a serialized event. Returns Malformed
    /// rather than throwing, so one bad record cannot fail a whole query.
    /// Requirement: logging 40.
    let index (payload: string) =
        try
            use document = JsonDocument.Parse payload
            let root = document.RootElement

            match tryString root "eventId", tryString root "eventType" with
            | Some eventId, Some eventType ->
                Ok
                    { EventId = EventId eventId
                      EventType = eventType
                      FaultId = tryString root "faultId" |> Option.map FaultId
                      CorrelationId = tryString root "correlationId" |> Option.map CorrelationId
                      Application = tryString root "application"
                      Operation = tryString root "operation"
                      Code = tryString root "code" |> Option.map FaultCode
                      Severity = tryString root "severity"
                      Timestamp =
                        tryString root "timestamp"
                        |> Option.bind (fun (t: string) ->
                            match DateTimeOffset.TryParse t with
                            | true, parsed -> Some parsed
                            | _ -> None) }
            | _ -> Result.Error(Malformed "event is missing eventId or eventType")
        with ex ->
            Result.Error(Malformed ex.Message)

    let private severityName =
        function
        | Diagnostic -> "Diagnostic"
        | Warning -> "Warning"
        | FaultSeverity.Error -> "Error"
        | Critical -> "Critical"

    /// Every supplied filter must match. Requirement: logging 27.
    let matches (query: Query) (event: Indexed) =
        let same selector expected actual =
            match expected with
            | None -> true
            | Some e -> actual |> Option.map selector |> Option.contains (selector e)

        [ query.EventId |> Option.forall (fun e -> e = event.EventId)
          same (fun (f: FaultId) -> f.Value) query.FaultId event.FaultId
          same (fun (c: CorrelationId) -> c.Value) query.CorrelationId event.CorrelationId
          query.Application |> Option.forall (fun a -> event.Application = Some a)
          query.Operation |> Option.forall (fun o -> event.Operation = Some o)
          same (fun (c: FaultCode) -> c.Value) query.Code event.Code
          query.Severity |> Option.forall (fun s -> event.Severity = Some(severityName s))
          query.EventType |> Option.forall (fun t -> t = event.EventType)
          query.From
          |> Option.forall (fun f -> event.Timestamp |> Option.forall (fun t -> t >= f))
          query.Until
          |> Option.forall (fun u -> event.Timestamp |> Option.forall (fun t -> t <= u)) ]
        |> List.forall id

    /// The durable store contract, expressed as functions so adapters need no
    /// inheritance and tests need no mocking framework.
    /// Requirements: logging 3, 28.
    type T =
        { Append: EventId -> string -> Async<Result<unit, Failure>>
          AppendBatch: (EventId * string) list -> Async<Result<unit, Failure>>
          Query: Query -> Async<Result<string list, Failure>> }
