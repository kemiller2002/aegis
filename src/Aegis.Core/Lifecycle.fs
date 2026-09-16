namespace Aegis

open System
open System.Security.Cryptography
open System.Text

/// The fault lifecycle: events are the record, and current state is a
/// projection derived from them rather than a mutated row.
/// Requirements: additional 3, 4, 17, 29, 30, 31, 32, 33, 34, 35, 36, 37.
module Lifecycle =

    /// Fingerprint inputs are deliberately narrow: identity-bearing but
    /// stable across occurrences. Timestamps, correlation ids, event ids and
    /// context values are all excluded. Requirement: additional 4.
    let fingerprint (fault: Fault) =
        let causeShape =
            match fault.Cause with
            | Some (CausedByException detail) -> detail.ExceptionType
            | Some (CausedByFault inner) -> $"fault:{inner.Code.Value}"
            | None -> "none"

        let canonical =
            String.Join(
                "|",
                [ fault.Code.Value
                  fault.Operation
                  fault.Application
                  string fault.Category
                  defaultArg fault.Owner "-"
                  causeShape ]
            )

        use sha = SHA256.Create()
        sha.ComputeHash(Encoding.UTF8.GetBytes canonical)
        |> Array.take 8
        |> Array.map (fun b -> b.ToString "x2")
        |> String.concat ""
        |> Fingerprint

    /// Requirements: additional 17, 29, 32, 33, 34.
    type State =
        | Active
        | AcknowledgedActive
        | Resolved
        | Superseded

    /// Derived view of one fault. Aggregate counters serve repeated transient
    /// faults without discarding individual occurrences.
    /// Requirements: additional 3, 31, 35, 52.
    type Projected =
        { Fault: Fault
          Fingerprint: Fingerprint
          State: State
          /// Current severity, which escalation advances. Requirement: additional 36.
          Severity: FaultSeverity
          FirstSeen: DateTimeOffset
          LastSeen: DateTimeOffset
          Occurrences: int
          Acknowledged: (RecoveryActor * DateTimeOffset) option
          Resolution: Resolution option
          SupersededBy: FaultId option
          Reopenings: int
          Attempts: RecoveryAttempt list
          EscalationHistory: (FaultSeverity * FaultSeverity * DateTimeOffset) list }

    let private record (fault: Fault) =
        { Fault = fault
          Fingerprint = fingerprint fault
          State = Active
          Severity = fault.Severity
          FirstSeen = fault.Timestamp
          LastSeen = fault.Timestamp
          Occurrences = 1
          Acknowledged = None
          Resolution = None
          SupersededBy = None
          Reopenings = 0
          Attempts = []
          EscalationHistory = [] }

    let private update key f (state: Map<string, Projected>) =
        match Map.tryFind key state with
        | None -> state
        | Some current -> Map.add key (f current) state

    /// Fold one event into the projection. Pure: the same event list always
    /// yields the same projection. Requirement: additional 31.
    let apply (state: Map<string, Projected>) (ev: AegisEvent) =
        match ev with
        | FaultRecorded fault ->
            let key = fault.Id.Value
            match Map.tryFind key state with
            | None -> Map.add key (record fault) state
            | Some existing ->
                Map.add
                    key
                    { existing with
                        Occurrences = existing.Occurrences + 1
                        LastSeen = max existing.LastSeen fault.Timestamp }
                    state
        | FaultSuppressed (fault, _) ->
            // A suppressed fault is still an occurrence: presentation is
            // throttled, diagnostic fidelity is not. Requirement: additional 26.
            let key = fault.Id.Value
            match Map.tryFind key state with
            | None -> Map.add key (record fault) state
            | Some existing ->
                Map.add key { existing with Occurrences = existing.Occurrences + 1 } state
        | FaultRepeated (id, at) ->
            state
            |> update id.Value (fun p ->
                { p with
                    Occurrences = p.Occurrences + 1
                    LastSeen = max p.LastSeen at })
        | FaultAcknowledged (id, actor, at) ->
            // Acknowledging must not mark it resolved. Requirement: additional 17.
            state
            |> update id.Value (fun p ->
                { p with
                    Acknowledged = Some(actor, at)
                    State = if p.State = Active then AcknowledgedActive else p.State })
        | RecoveryStarted (id, attempt) ->
            state |> update id.Value (fun p -> { p with Attempts = p.Attempts @ [ attempt ] })
        | RecoveryConcluded (id, attemptNumber, outcome, _) ->
            state
            |> update id.Value (fun p ->
                { p with
                    Attempts =
                        p.Attempts
                        |> List.map (fun a ->
                            if a.AttemptNumber = attemptNumber then { a with Outcome = outcome } else a) })
        | FaultEscalated (id, previous, current, at) ->
            state
            |> update id.Value (fun p ->
                { p with
                    Severity = current
                    EscalationHistory = p.EscalationHistory @ [ previous, current, at ] })
        | FaultResolved (id, resolution) ->
            state
            |> update id.Value (fun p ->
                { p with
                    State = Resolved
                    Resolution = Some resolution })
        | FaultReopened (id, at, _) ->
            state
            |> update id.Value (fun p ->
                { p with
                    State = Active
                    Resolution = None
                    Reopenings = p.Reopenings + 1
                    LastSeen = max p.LastSeen at })
        | FaultSuperseded (superseded, by, _) ->
            state
            |> update superseded.Value (fun p ->
                { p with
                    State = Superseded
                    SupersededBy = Some by })
        | SinkFailed _ -> state

    /// Project a whole event history. Requirement: additional 31.
    let project events = events |> List.fold apply Map.empty

    /// Faults still demanding attention: neither resolved nor superseded.
    let active projection =
        projection
        |> Map.toList
        |> List.map snd
        |> List.filter (fun p ->
            match p.State with
            | Active
            | AcknowledgedActive -> true
            | Resolved
            | Superseded -> false)

    /// Group by fingerprint so repeated occurrences of one underlying problem
    /// aggregate, without losing the individual records.
    /// Requirements: additional 3, 46, 52.
    let byFingerprint projection =
        projection
        |> Map.toList
        |> List.map snd
        |> List.groupBy (fun p -> p.Fingerprint)
        |> Map.ofList

    /// Whether a newly observed fault is a recurrence of a known one, which
    /// distinguishes reopening from an unrelated new occurrence.
    /// Requirement: additional 33.
    let recurrenceOf projection (candidate: Fault) =
        let fp = fingerprint candidate
        projection
        |> Map.toList
        |> List.map snd
        |> List.filter (fun p -> p.Fingerprint = fp && p.Fault.Id <> candidate.Id)
        |> List.sortByDescending (fun p -> p.LastSeen)
        |> List.tryHead
