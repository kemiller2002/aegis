namespace Aegis

open System

/// The known-fault catalog and the structured guidance it offers agents.
/// Requirements: additional 14, 42.
module Catalog =

    /// Guidance is advisory data. It cannot grant permission: prohibited
    /// actions are explicit, and nothing here bypasses the recovery authority.
    /// Requirement: additional 42.
    type Guidance =
        { LikelyCauses: string list
          EvidenceToInspect: string list
          SafeChecks: string list
          /// Actions an agent must not take for this fault, whatever else it
          /// infers. Requirement: additional 42.
          ProhibitedActions: Recovery.Capability list
          ExpectedTransitions: string list
          Documentation: string option }

    let noGuidance =
        { LikelyCauses = []
          EvidenceToInspect = []
          SafeChecks = []
          ProhibitedActions = []
          ExpectedTransitions = []
          Documentation = None }

    /// Requirement: additional 14.
    type Entry =
        { Code: FaultCode
          Title: string
          Description: string
          Category: FailureCategory
          DefaultSeverity: FaultSeverity
          RetryEligible: bool
          AutomaticRecoveryAllowed: bool
          NotifyUser: bool
          EscalationGuidance: string option
          Guidance: Guidance }

    type T = Map<string, Entry>

    let empty: T = Map.empty

    let add (entry: Entry) (catalog: T) = Map.add entry.Code.Value entry catalog

    let lookup (code: FaultCode) (catalog: T) = Map.tryFind code.Value catalog

    /// Whether an agent may attempt a capability for this fault: the catalog
    /// can forbid, but it can never permit on its own -- the recovery
    /// authority still decides. Requirement: additional 42.
    let permits (catalog: T) (code: FaultCode) (capability: Recovery.Capability) =
        match lookup code catalog with
        | None -> true
        | Some entry ->
            entry.AutomaticRecoveryAllowed
            && not (entry.Guidance.ProhibitedActions |> List.contains capability)

    /// Apply the catalog's defaults to a fault that arrived without them,
    /// so classification is consistent between humans and agents.
    /// Requirement: additional 14.
    let classify (catalog: T) (fault: Fault) =
        match lookup fault.Code catalog with
        | None -> fault
        | Some entry ->
            { fault with
                Category = entry.Category
                Severity = entry.DefaultSeverity }

    /// A starting catalog for the faults this library itself raises.
    let builtIn =
        empty
        |> add
            { Code = FaultCode "AEGIS.GITHUB.AUTHENTICATION_FAILED"
              Title = "GitHub authentication failed"
              Description = "A GitHub request was rejected because the credentials are missing, expired or insufficient."
              Category = SecurityFailure
              DefaultSeverity = FaultSeverity.Error
              RetryEligible = false
              AutomaticRecoveryAllowed = true
              NotifyUser = true
              EscalationGuidance = Some "Escalate to Critical if reauthentication fails twice."
              Guidance =
                { LikelyCauses =
                    [ "the stored token has expired"
                      "the token lacks the required scope"
                      "the installation was revoked" ]
                  EvidenceToInspect = [ "the fault's correlation id across the integration boundary"; "token expiry metadata" ]
                  SafeChecks = [ "verify repository access with the current credentials" ]
                  ProhibitedActions = [ Recovery.CanQuarantine; Recovery.CanReprocess ]
                  ExpectedTransitions = [ "AuthenticationRequired" ]
                  Documentation = Some "docs/architecture/README.md" } }
        |> add
            { Code = FaultCode "AEGIS.NETWORK.UNAVAILABLE"
              Title = "Network unavailable"
              Description = "A dependency could not be reached."
              Category = InfrastructureFailure
              DefaultSeverity = FaultSeverity.Warning
              RetryEligible = true
              AutomaticRecoveryAllowed = true
              NotifyUser = false
              EscalationGuidance = Some "Escalate if the condition persists beyond the transient window."
              Guidance =
                { LikelyCauses = [ "transient connectivity loss"; "the dependency is down" ]
                  EvidenceToInspect = [ "occurrence count and consecutive failures"; "whether other dependencies also fail" ]
                  SafeChecks = [ "retry once with backoff" ]
                  ProhibitedActions = [ Recovery.CanQuarantine ]
                  ExpectedTransitions = [ "Offline"; "DegradedApplication" ]
                  Documentation = None } }
        |> add
            { Code = FaultCode "AEGIS.DATA.HASH_MISMATCH"
              Title = "Stored data failed its integrity check"
              Description = "Persisted content does not match its recorded digest, so it cannot be trusted."
              Category = DataFailure
              DefaultSeverity = FaultSeverity.Critical
              RetryEligible = false
              // Correctness is not established, so nothing automatic may write.
              AutomaticRecoveryAllowed = false
              NotifyUser = true
              EscalationGuidance = Some "Treat as application-unsafe until a human confirms the data."
              Guidance =
                { LikelyCauses = [ "an interrupted write"; "concurrent modification"; "manual edit of stored state" ]
                  EvidenceToInspect = [ "the expected and actual digests"; "the last successful write" ]
                  SafeChecks = [ "open the repository read-only and compare against history" ]
                  ProhibitedActions = [ Recovery.CanRetry; Recovery.CanReprocess; Recovery.CanReload ]
                  ExpectedTransitions = [ "ReadOnly" ]
                  Documentation = None } }
