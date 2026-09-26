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

    /// What a stored event records about its contribution provenance:
    /// `Absent` for an event written before provenance existed, or without
    /// it (unattributed, never inferred); `Carried` for a block, which is
    /// re-classified on read so malformed provenance (including a stored
    /// `"provenance": null`) is reported rather than silently dropped; and
    /// `Rejected` for an event whose block the writer refused and recorded
    /// as `provenanceRejected` -- distinguishable from a legacy event.
    /// Requirements: AEG-PROV-007, AEG-PROV-008.
    let storedProvenance (payload: string) : Result<StoredProvenance, Failure> =
        try
            use document = JsonDocument.Parse payload
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                Result.Error(Malformed "event is not a JSON object")
            else
                match root.TryGetProperty "provenance", root.TryGetProperty "provenanceRejected" with
                | (true, _), (true, _) -> Result.Error(Malformed "event carries both provenance and provenanceRejected")
                | (true, value), _ ->
                    match Provenance.receive (value.GetRawText()) with
                    | Ok block -> Ok(StoredProvenance.Carried block)
                    | Result.Error problems -> Result.Error(Malformed("provenance: " + String.Join("; ", problems)))
                | _, (true, reason) when reason.ValueKind = JsonValueKind.String && not (Provenance.isBlank (reason.GetString())) ->
                    Ok(StoredProvenance.Rejected(reason.GetString()))
                | _, (true, _) -> Result.Error(Malformed "provenanceRejected must be a non-empty string")
                | _ -> Ok StoredProvenance.Absent
        with ex ->
            Result.Error(Malformed ex.Message)

    /// The contribution provenance block a stored event carries: `Ok None`
    /// only for a legacy or unattributed event. An event whose block was
    /// rejected when written is `Error(Rejected reason)`, never `Ok None`,
    /// so it cannot be mistaken for an unattributed one; malformed
    /// provenance is `Error(Malformed ...)`. Requirements: AEG-PROV-007, AEG-PROV-008.
    let provenanceOf (payload: string) : Result<ProvenanceBlock option, Failure> =
        storedProvenance payload
        |> Result.bind (function
            | StoredProvenance.Absent -> Ok None
            | StoredProvenance.Carried block -> Ok(Some block)
            | StoredProvenance.Rejected reason -> Result.Error(Rejected $"provenance was rejected when written: {reason}"))

    /// Accumulate every fault's contribution provenance from stored event
    /// payloads, in stream order. Unreadable events fail the projection
    /// rather than vanishing from it; events whose provenance was rejected
    /// when written are listed under `Rejected`. Requirement: AEG-PROV-004.
    let provenanceHistory (payloads: string list) : Result<Map<string, FaultProvenance>, Failure> =
        let read payload =
            match index payload, storedProvenance payload with
            | Ok indexed, Ok stored -> Ok(indexed, stored)
            | Result.Error failure, _
            | _, Result.Error failure -> Result.Error failure

        let rec collect acc remaining =
            match remaining with
            | [] -> Ok(List.rev acc)
            | payload :: rest ->
                match read payload with
                | Ok item -> collect (item :: acc) rest
                | Result.Error failure -> Result.Error failure

        collect [] payloads
        |> Result.map (fun items ->
            items
            |> List.choose (fun (indexed, stored) ->
                indexed.FaultId |> Option.map (fun faultId -> faultId, ($"{indexed.EventType} {indexed.EventId.Value}", stored)))
            |> List.groupBy fst
            |> List.map (fun (faultId, entries) -> faultId.Value, ProvenanceHistory.ofStored faultId (entries |> List.map snd))
            |> Map.ofList)

    let private severityName =
        function
        | FaultSeverity.Diagnostic -> "Diagnostic"
        | FaultSeverity.Warning -> "Warning"
        | FaultSeverity.Error -> "Error"
        | FaultSeverity.Critical -> "Critical"

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
