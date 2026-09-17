namespace Aegis

open System

/// Containment: stopping repeated known failures from doing more damage.
/// Circuit state, quarantine of unprocessable data, and dead-lettering of
/// work that cannot be completed.
/// Requirements: additional 6, 7, 8.
module Containment =

    /// Aegis does not implement a resilience framework; it exposes enough
    /// structured state for an infrastructure adapter to implement one, and
    /// the behaviour stays explicit and observable.
    /// Requirement: additional 6.
    type Circuit =
        | Closed
        | Open of until: DateTimeOffset
        | HalfOpen

    type CircuitPolicy =
        { ConsecutiveFailures: int
          OpenFor: TimeSpan }

    /// Derive circuit state from observed history rather than hidden counters,
    /// so the decision is reproducible and inspectable.
    /// Requirement: additional 6.
    let circuit (policy: CircuitPolicy) (now: DateTimeOffset) (consecutiveFailures: int) (lastFailure: DateTimeOffset option) =
        match lastFailure with
        | Some last when consecutiveFailures >= policy.ConsecutiveFailures ->
            let until = last + policy.OpenFor
            if now < until then Open until else HalfOpen
        | _ -> Closed

    /// Whether a call may proceed. HalfOpen permits exactly one trial call,
    /// which is the point of the state.
    let permits =
        function
        | Closed
        | HalfOpen -> true
        | Open _ -> false

    type Quarantine = Map<string, Quarantined>

    let noQuarantine: Quarantine = Map.empty

    let quarantine (item: Quarantined) (store: Quarantine) = Map.add item.SourceId item store

    /// Known-bad data is not processed again while it remains quarantined.
    /// Requirement: additional 7.
    let isQuarantined (sourceId: string) (store: Quarantine) =
        match Map.tryFind sourceId store with
        | Some item -> item.Released.IsNone
        | None -> false

    let release at (sourceId: string) (store: Quarantine) =
        match Map.tryFind sourceId store with
        | Some item -> Map.add sourceId { item with Released = Some at } store
        | None -> store

    let held (store: Quarantine) =
        store |> Map.toList |> List.map snd |> List.filter (fun i -> i.Released.IsNone)

    /// Dead-lettering is deterministic and policy-driven: an item is
    /// dead-lettered exactly when its recovery budget is spent.
    /// Requirement: additional 8.
    let shouldDeadLetter (maxAttempts: int) (attempts: RecoveryAttempt list) =
        let failed =
            attempts
            |> List.filter (fun a ->
                match a.Outcome with
                | FailedWith _ -> true
                | Succeeded
                | AwaitingVerification -> false)

        List.length failed >= maxAttempts

    let deadLetter at itemId payloadReference (fault: Fault) (attempts: RecoveryAttempt list) reason =
        { ItemId = itemId
          PayloadReference = payloadReference
          FaultId = fault.Id
          Code = fault.Code
          Attempts = attempts
          FinalReason = reason
          At = at
          RequiresManualIntervention =
            match fault.Recovery with
            | ManualIntervention
            | ReadOnlyRecovery
            | NoRecovery -> true
            | _ -> false
          Reprocessable =
            match fault.Persistence with
            | Transient
            | UnknownPersistence -> true
            | Persistent
            | Permanent
            | RequiresIntervention -> false }

    /// Quarantining an item is an event, so it persists through the same
    /// sinks, redaction and retention path as any other record.
    /// Requirement: additional 7.
    let quarantinedEvent (item: Quarantined) = ItemQuarantined item

    let releasedEvent (sourceId: string) (at: DateTimeOffset) = ItemReleased(sourceId, at)

    /// Requirement: additional 8.
    let deadLetteredEvent (item: DeadLettered) = ItemDeadLettered item

    /// Rebuild the quarantine from persisted history, so what is held aside
    /// survives a restart instead of living only in memory.
    /// Requirement: additional 7.
    let fromHistory (events: AegisEvent list) =
        events
        |> List.fold
            (fun store ev ->
                match ev with
                | ItemQuarantined item -> Map.add item.SourceId item store
                | ItemReleased (sourceId, at) ->
                    match Map.tryFind sourceId store with
                    | Some item -> Map.add sourceId { item with Released = Some at } store
                    | None -> store
                | _ -> store)
            noQuarantine

    /// Dead letters recovered from persisted history, for a reprocessing pass.
    /// Requirement: additional 8.
    let deadLettersFromHistory (events: AegisEvent list) =
        events
        |> List.choose (function
            | ItemDeadLettered item -> Some item
            | _ -> None)

    /// Which dead letters may be reprocessed without a human.
    let reprocessable (letters: DeadLettered list) =
        letters |> List.filter (fun l -> l.Reprocessable && not l.RequiresManualIntervention)
