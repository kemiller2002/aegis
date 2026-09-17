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

    /// Requirement: additional 7.
    type Quarantined =
        { SourceId: string
          /// A reference to the payload, not the payload, so quarantine
          /// storage follows the same sensitive-data rules as everything else.
          PayloadReference: string
          FaultId: FaultId
          Code: FaultCode
          Reason: string
          At: DateTimeOffset
          RetryEligible: bool
          Released: DateTimeOffset option }

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

    /// Requirement: additional 8. Carries enough to identify the item,
    /// understand why it failed, see what was tried, and decide whether a
    /// human is needed.
    type DeadLettered =
        { ItemId: string
          PayloadReference: string
          FaultId: FaultId
          Code: FaultCode
          Attempts: RecoveryAttempt list
          FinalReason: string
          At: DateTimeOffset
          RequiresManualIntervention: bool
          Reprocessable: bool }

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
