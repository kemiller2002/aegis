namespace Aegis

open System

/// What Aegis asks SDE for, and nothing more.
///
/// A fault may propose a transition; SDE decides whether it is legal from the
/// current state. Aegis never applies one, so nothing here mutates state or
/// bypasses a rule -- these are requests, and they are values.
/// Requirements: core 9; additional 19; logging 44.
module Sde =

    /// A requested transition, with why it is requested so SDE and a reviewer
    /// can judge it. Requirement: core 9.
    type Proposal =
        { Transition: string
          Because: FaultCode option
          /// What Aegis believes the transition implies, for SDE to check
          /// against its own rules rather than to trust.
          Implies: string list }

    let private proposal name because implies =
        { Transition = name
          Because = because
          Implies = implies }

    /// The transition a fault suggests. The named example in the requirements
    /// is GitHubAuthenticationFailed proposing AuthenticationRequired.
    /// Requirement: core 9.
    let forFault (fault: Fault) =
        match fault.Category, fault.Impact, fault.Recovery with
        | SecurityFailure, _, RecoveryPolicy.Reauthenticate ->
            Some(proposal "AuthenticationRequired" (Some fault.Code) [ "credentials must be re-established" ])
        | DataFailure, ApplicationUnsafe, _ ->
            Some(proposal "ReadOnly" (Some fault.Code) [ "stored data is not trusted"; "writes must be prevented" ])
        | _, ApplicationUnsafe, _ ->
            Some(proposal "RestrictedOperation" (Some fault.Code) [ "continuing normally is unsafe" ])
        | _, DegradedApplication, _ ->
            Some(proposal "Degraded" (Some fault.Code) [ "some features are unavailable" ])
        | InfrastructureFailure, FeatureUnavailable, _ ->
            Some(proposal "Offline" (Some fault.Code) [ "a dependency is unreachable" ])
        | _ -> None

    /// Persistence state may influence application state where relevant, e.g.
    /// DiagnosticPersistenceAvailable becoming DiagnosticPersistenceDegraded.
    /// Requirement: logging 44.
    let forPersistence (state: Presentation.PersistenceState) =
        match state with
        | Presentation.Synchronized -> Some(proposal "DiagnosticPersistenceAvailable" None [])
        | Presentation.Queued _ ->
            Some(proposal "DiagnosticPersistenceDegraded" None [ "diagnostics are queued rather than durable" ])
        | Presentation.Unavailable
        | Presentation.LastSynchronizationFailed _ ->
            Some(
                proposal
                    "DiagnosticPersistenceUnavailable"
                    None
                    [ "diagnostics are not being persisted"; "audit-required events may be lost" ]
            )

    /// The safe mode a fault recommends, expressed as a transition request so
    /// it goes through the same door as everything else.
    /// Requirement: additional 19.
    let forSafeMode (mode: Recovery.SafeMode) =
        let name =
            match mode with
            | Recovery.ReadOnly -> "ReadOnly"
            | Recovery.OfflineMode -> "Offline"
            | Recovery.FeatureDisabled -> "FeatureDisabled"
            | Recovery.DiagnosticsOnly -> "DiagnosticsOnly"
            | Recovery.RestrictedOperation -> "RestrictedOperation"

        proposal name None [ "requested because continuing normally is unsafe" ]
