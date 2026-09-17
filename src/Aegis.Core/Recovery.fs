namespace Aegis

open System

/// Recovery: what Aegis may propose, what an external authority permits, and
/// what actually happened.
///
/// Aegis never decides that a recovery action is legal. The requirements are
/// explicit that SDE owns whether a transition is valid from the current
/// state, so authorization is injected. That keeps the boundary honest while
/// SDE lives outside this repository, and keeps every decision testable.
/// Requirements: core 8, 9, 21; additional 15, 16, 19, 28, 37, 38, 39.
module Recovery =

    /// Machine-readable capabilities an agent or automated component may
    /// inspect to see which actions are even available.
    /// Requirement: additional 28.
    type Capability =
        | CanRetry
        | CanReauthenticate
        | CanReload
        | CanQuarantine
        | CanReprocess
        | CanOpenReadOnly
        | CanRestoreSink

    /// The authority's answer. RequiresApproval is distinct from Denied: one
    /// is "not without a human", the other is "not at all".
    /// Requirement: core 9.
    type Decision =
        | Authorized
        | RequiresApproval of reason: string
        | Denied of reason: string

    /// Supplied by the application or SDE integration. Requirement: core 9.
    type Authority = { Authorize: Fault -> RecoveryPolicy -> Decision }

    /// An authority that permits nothing, so the safe default is inaction
    /// rather than unauthorized recovery.
    let denyAll =
        { Authorize = fun _ _ -> Denied "no recovery authority is configured" }

    /// Why a recovery was not attempted, so a skipped recovery is never
    /// silent. Requirement: core 7.
    type Refusal =
        | NotAuthorized of reason: string
        | NeedsApproval of reason: string
        | AttemptsExhausted of attempts: int
        | UnsafeToRepeat
        | NothingToDo

    /// Requirement: additional 19. Aegis recommends; the authority decides.
    type SafeMode =
        | ReadOnly
        | OfflineMode
        | FeatureDisabled
        | DiagnosticsOnly
        | RestrictedOperation

    /// Requirements: additional 16, 39.
    type ObligationKind =
        | Reauthenticate
        | ResolveCorruptData
        | ReviewFailedOperation
        | ReprocessDeadLetter
        | InvestigateSchemaMismatch
        | RestoreSink

    type Obligation =
        { FaultId: FaultId
          Kind: ObligationKind
          Raised: DateTimeOffset
          /// Stays visible until explicitly resolved or superseded.
          /// Requirement: additional 16.
          Discharged: DateTimeOffset option }

    /// Which capabilities a fault's policy actually offers. An agent reads
    /// this instead of guessing. Requirement: additional 28.
    let capabilities (fault: Fault) =
        match fault.Recovery with
        | Retry _ -> [ CanRetry ]
        | RecoveryPolicy.Reauthenticate -> [ CanReauthenticate ]
        | Reload
        | Refresh -> [ CanReload ]
        | ReadOnlyRecovery -> [ CanOpenReadOnly ]
        | ManualIntervention -> []
        | Continue
        | AbortOperation
        | RestartApplication
        | NoRecovery -> []

    /// The safe mode a fault's impact suggests. Requirement: additional 19.
    let recommendedMode (fault: Fault) =
        match fault.Impact, fault.Category with
        | ApplicationUnsafe, DataFailure -> Some ReadOnly
        | ApplicationUnsafe, _ -> Some RestrictedOperation
        | DegradedApplication, _ -> Some FeatureDisabled
        | FeatureUnavailable, InfrastructureFailure -> Some OfflineMode
        | FeatureUnavailable, _ -> Some FeatureDisabled
        | OperationOnly, _ -> None

    /// Faults that cannot be safely recovered automatically raise an explicit
    /// obligation. Requirements: additional 16, 39.
    let obligationFor (fault: Fault) =
        match fault.Recovery, fault.Category with
        | RecoveryPolicy.Reauthenticate, _ -> Some Reauthenticate
        | ManualIntervention, DataFailure -> Some ResolveCorruptData
        | ManualIntervention, ConfigurationFailure -> Some InvestigateSchemaMismatch
        | ManualIntervention, _ -> Some ReviewFailedOperation
        | ReadOnlyRecovery, DataFailure -> Some ResolveCorruptData
        | _ -> None

    let raiseObligation at (fault: Fault) =
        obligationFor fault
        |> Option.map (fun kind ->
            { FaultId = fault.Id
              Kind = kind
              Raised = at
              Discharged = None })

    let discharge at (obligation: Obligation) =
        { obligation with Discharged = Some at }

    let outstanding obligations =
        obligations |> List.filter (fun o -> o.Discharged.IsNone)

    /// What a recovery attempt did, including the events to record so the
    /// attempt is auditable. Requirement: additional 37.
    type Attempted =
        { Outcome: RecoveryOutcome
          Attempt: RecoveryAttempt
          Events: AegisEvent list }

    type Result =
        | Attempt of Attempted
        | Refused of Refusal * AegisEvent list

    let private maxAttempts =
        function
        | Retry (attempts, _) -> attempts
        | _ -> 1

    /// Attempt recovery once.
    ///
    /// `authority` decides legality, `perform` does the work, and `verify`
    /// answers whether the condition is actually gone: Some true means
    /// verified recovered, Some false means it is not, None means
    /// verification is not possible here. Recovery counts as succeeded only
    /// when verification does not contradict it, because an action returning
    /// without throwing is not evidence that it worked.
    /// Requirements: core 9, 21; additional 15, 37, 38.
    let attempt
        (authority: Authority)
        (actor: RecoveryActor)
        (at: DateTimeOffset)
        (attemptNumber: int)
        (idempotent: bool)
        (perform: RecoveryPolicy -> Result<unit, string>)
        (verify: unit -> bool option)
        (fault: Fault)
        =
        let action = fault.Recovery

        let record outcome =
            { Action = action
              AttemptNumber = attemptNumber
              Actor = actor
              Timestamp = at
              CorrelationId = fault.CorrelationId
              Outcome = outcome }

        match action with
        | NoRecovery
        | Continue -> Refused(NothingToDo, [])
        | ManualIntervention -> Refused(NeedsApproval "the fault requires manual intervention", [])
        | _ ->
            match authority.Authorize fault action with
            | Denied reason -> Refused(NotAuthorized reason, [])
            | RequiresApproval reason -> Refused(NeedsApproval reason, [])
            | Authorized ->
                if attemptNumber > maxAttempts action then
                    Refused(AttemptsExhausted(maxAttempts action), [])
                // A failed read may be repeated; a partially completed write
                // may not. Requirement: core 21.
                elif not idempotent && attemptNumber > 1 then
                    Refused(UnsafeToRepeat, [])
                else
                    let started = record AwaitingVerification

                    let outcome =
                        match perform action with
                        | Result.Error reason -> FailedWith reason
                        | Ok () ->
                            match verify () with
                            | Some true -> Succeeded
                            | Some false -> FailedWith "recovery ran but the condition persists"
                            | None -> AwaitingVerification

                    { Outcome = outcome
                      Attempt = record outcome
                      Events =
                        [ RecoveryStarted(fault.Id, started)
                          RecoveryConcluded(fault.Id, attemptNumber, outcome, at) ] }
                    |> Attempt
