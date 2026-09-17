namespace Aegis

open System

/// Schema identifiers. Serialized payloads carry these so tooling never
/// depends implicitly on whatever the current shape happens to be.
/// Requirements: core 37, logging 12.
module Schema =
    [<Literal>]
    let Fault = "aegis/fault/v1"

    [<Literal>]
    let Event = "aegis/event/v1"

/// Sortable, unique identifiers. Time-ordered prefix plus random suffix gives
/// uniqueness and lexicographic time ordering, so file names and event
/// sequences sort naturally. Requirements: logging 8, 24, 33.
module Id =
    let private alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    let private encode (value: int64) (width: int) =
        let rec loop v n acc =
            if n = 0 then acc
            else loop (v / 32L) (n - 1) (string alphabet.[int (v % 32L)] + acc)
        loop value width ""

    /// 26-character sortable identifier: 10 chars of timestamp, 16 of randomness.
    let generate (now: DateTimeOffset) (randomness: int64 * int64) =
        let hi, lo = randomness
        encode (now.ToUnixTimeMilliseconds()) 10 + encode (abs hi) 8 + encode (abs lo) 8

type FaultId =
    | FaultId of string

    member this.Value = match this with FaultId v -> v

type EventId =
    | EventId of string

    member this.Value = match this with EventId v -> v

type CorrelationId =
    | CorrelationId of string

    member this.Value = match this with CorrelationId v -> v

/// Stable machine-readable fault identity. Human-readable messages may change;
/// codes must not. Requirement: core 4.
type FaultCode =
    | FaultCode of string

    member this.Value = match this with FaultCode v -> v

/// Requirement: core 2. Domain failures stay in the domain model; these
/// describe unexpected operational failures Aegis handles.
type FailureCategory =
    | DomainFailure
    | InfrastructureFailure
    | IntegrationFailure
    | DataFailure
    | ConfigurationFailure
    | SecurityFailure
    | ProgrammingDefect
    | UnknownFailure

/// Requirement: core 18. Deliberately few levels.
type FaultSeverity =
    | Diagnostic
    | Warning
    | Error
    | Critical

/// Requirement: core 39. Whether the application can safely continue.
type FaultImpact =
    | OperationOnly
    | FeatureUnavailable
    | DegradedApplication
    | ApplicationUnsafe

/// Requirement: additional 18. Influences retry, escalation and notification.
type Persistence =
    | Transient
    | Persistent
    | Permanent
    | UnknownPersistence
    | RequiresIntervention

/// Requirement: core 8. Aegis describes allowable recovery; SDE decides
/// whether a transition is legal from the current state.
type RecoveryPolicy =
    | Retry of attempts: int * backoff: Backoff
    | Reauthenticate
    | Reload
    | Refresh
    | Continue
    | AbortOperation
    | RestartApplication
    | ManualIntervention
    /// Recover without mutating data, for integrity faults where correctness
    /// has not yet been established. Requirement: core 20.
    | ReadOnlyRecovery
    | NoRecovery

and Backoff =
    | Immediate
    | Fixed of TimeSpan
    | Exponential of initial: TimeSpan

/// Requirement: additional 27. Classification drives persistence eligibility,
/// redaction, export and agent access. Secret values are never persisted.
type ContextValue =
    | Public of string
    | Internal of string
    | Sensitive of string
    | Secret of string

    member this.Raw =
        match this with
        | Public v
        | Internal v
        | Sensitive v
        | Secret v -> v

/// Where a failure sits in the system, which bounds how far it reaches.
/// Requirement: additional 43.
type FailureDomain =
    | LocalOperation
    | FeatureDomain
    | IntegrationDomain
    | RepositoryDomain
    | ApplicationDomain
    | EnvironmentDomain
    | ExternalDependency

/// Likely operational reach, complementing FaultImpact rather than replacing
/// it: impact says how badly, radius says how widely.
/// Requirement: additional 44.
type BlastRadius =
    | OneItem
    | OneOperation
    | OneFeature
    | OneRepository
    | OneSession
    | EntireApplication

/// Retention intent travels with the event; an adapter may enforce it.
/// Requirement: logging 26.
type Retention =
    | RetainIndefinitely
    | RetainDays of int
    | ArchiveAfterDays of int
    | DiagnosticOnly
    | AuditRequired

/// A structured step leading up to a fault. Bounded trails live in the
/// Diagnostics module; the type is here so a fault can carry them.
/// Requirement: additional 2.
type Breadcrumb =
    { At: DateTimeOffset
      Category: string
      Message: string
      Data: Map<string, ContextValue> }

/// Structured, entirely optional environment metadata.
/// Requirements: additional 10, 11.
type EnvironmentInfo =
    { ApplicationVersion: string option
      BuildVersion: string option
      CommitSha: string option
      Branch: string option
      DeploymentEnvironment: string option
      RuntimeVersion: string option
      OperatingSystem: string option
      BrowserVersion: string option
      SchemaVersion: string option
      ComponentVersions: Map<string, string> }

/// A reference to a state snapshot, never the state itself.
/// Requirement: additional 12.
type SnapshotReference =
    { Location: string
      Digest: string
      Summary: string
      CapturedAt: DateTimeOffset }

/// The optional diagnostic material a fault may carry. Grouped so the fault
/// record stays readable and so callers that have none say so once.
/// Requirements: additional 2, 10, 11, 12.
type FaultDiagnostics =
    { Breadcrumbs: Breadcrumb list
      Environment: EnvironmentInfo option
      Snapshot: SnapshotReference option }

/// Preserved original exception detail, kept separate from the domain-facing
/// fault representation. Requirement: core 17.
type ExceptionDetail =
    { ExceptionType: string
      Message: string
      StackTrace: string option
      Inner: ExceptionDetail option }

/// Requirement: core 15. Causal chain, not a flattened message.
type FaultCause =
    | CausedByFault of Fault
    | CausedByException of ExceptionDetail

/// The common fault representation. Requirement: core 3.
and Fault =
    { Id: FaultId
      CorrelationId: CorrelationId
      Timestamp: DateTimeOffset
      Application: string
      ApplicationVersion: string option
      Operation: string
      Category: FailureCategory
      Code: FaultCode
      Severity: FaultSeverity
      Impact: FaultImpact
      /// Requirement: additional 43.
      Domain: FailureDomain
      /// Requirement: additional 44.
      Radius: BlastRadius
      /// Requirement: logging 26.
      Retention: Retention
      Persistence: Persistence
      Owner: string option
      /// Dependencies this fault implicates, outermost first, e.g.
      /// ["Chrona"; "GitHubIntegration"; "GitHubApi"]. Requirement: additional 45.
      Dependencies: string list
      UserMessage: string
      TechnicalDetails: string option
      Context: Map<string, ContextValue>
      Recovery: RecoveryPolicy
      /// Requirements: additional 2, 10, 11, 12.
      Diagnostics: FaultDiagnostics
      Cause: FaultCause option }

/// Stable identity for "is this the same underlying problem as before?".
/// Deliberately excludes timestamps, correlation ids and secrets, since those
/// make every occurrence unique. Requirement: additional 4.
type Fingerprint =
    | Fingerprint of string

    member this.Value = match this with Fingerprint v -> v

/// Who or what initiated a recovery. Requirement: additional 38.
type RecoveryActor =
    | User
    | Application
    | Agent
    | ScheduledProcess
    | Integration
    | Operator

/// A recovery operation returning without throwing is not success: where
/// verification is possible, recovery counts only once verified.
/// Requirement: additional 15.
type RecoveryOutcome =
    | Succeeded
    | FailedWith of string
    | AwaitingVerification

/// Requirement: additional 37. Makes automated remediation auditable.
type RecoveryAttempt =
    { Action: RecoveryPolicy
      AttemptNumber: int
      Actor: RecoveryActor
      Timestamp: DateTimeOffset
      CorrelationId: CorrelationId
      Outcome: RecoveryOutcome }

/// Requirement: additional 32. Resolution never erases the original history.
type ResolutionKind =
    | ResolvedAutomatically
    | ResolvedManually
    | NoLongerApplies

type Resolution =
    { Timestamp: DateTimeOffset
      Kind: ResolutionKind
      Action: RecoveryPolicy option
      Verified: bool }

/// A fault with no diagnostic material attached.
[<AutoOpen>]
module FaultDefaults =
    let noDiagnostics =
        { Breadcrumbs = []
          Environment = None
          Snapshot = None }

    let unknownEnvironment =
        { ApplicationVersion = None
          BuildVersion = None
          CommitSha = None
          Branch = None
          DeploymentEnvironment = None
          RuntimeVersion = None
          OperatingSystem = None
          BrowserVersion = None
          SchemaVersion = None
          ComponentVersions = Map.empty }

/// Data that could not be processed, held aside so it is not retried
/// endlessly. Carries a reference to the payload rather than the payload, so
/// quarantine storage follows the same sensitive-data rules as everything
/// else. Requirement: additional 7.
type Quarantined =
    { SourceId: string
      PayloadReference: string
      FaultId: FaultId
      Code: FaultCode
      Reason: string
      At: DateTimeOffset
      RetryEligible: bool
      Released: DateTimeOffset option }

/// Work that could not be completed after its recovery budget was spent.
/// Requirement: additional 8.
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

/// Persisted lifecycle events, not only the originating fault. Lifecycle
/// changes are new events, never mutations of history.
/// Requirements: logging 5; additional 29, 30.
type AegisEvent =
    | FaultRecorded of Fault
    | FaultSuppressed of Fault * reason: string
    /// A further occurrence of a fault already recorded. Requirement: additional 35.
    | FaultRepeated of FaultId * at: DateTimeOffset
    /// Acknowledgement is not resolution. Requirement: additional 17.
    | FaultAcknowledged of FaultId * by: RecoveryActor * at: DateTimeOffset
    | RecoveryStarted of FaultId * RecoveryAttempt
    | RecoveryConcluded of FaultId * attemptNumber: int * RecoveryOutcome * at: DateTimeOffset
    /// Severity is never overwritten without historical evidence. Requirement: additional 36.
    | FaultEscalated of FaultId * previous: FaultSeverity * current: FaultSeverity * at: DateTimeOffset
    | FaultResolved of FaultId * Resolution
    /// Reopening is explicit. Requirement: additional 33.
    | FaultReopened of FaultId * at: DateTimeOffset * reason: string
    /// A newer fault describes the condition better. Requirement: additional 34.
    | FaultSuperseded of superseded: FaultId * by: FaultId * at: DateTimeOffset
    /// Requirement: additional 7 -- quarantine is persisted, not just held.
    | ItemQuarantined of Quarantined
    | ItemReleased of sourceId: string * at: DateTimeOffset
    /// Requirement: additional 8 -- dead-lettering is persisted too.
    | ItemDeadLettered of DeadLettered
    | SinkFailed of sinkName: string * code: FaultCode * message: string

    /// The fault this event concerns, where it carries the whole record.
    member this.Fault =
        match this with
        | FaultRecorded f
        | FaultSuppressed (f, _) -> Some f
        | _ -> None

    /// The fault identity this event concerns, for reconstructing one fault's
    /// history from the event stream. Requirement: logging 23.
    member this.FaultId =
        match this with
        | FaultRecorded f
        | FaultSuppressed (f, _) -> Some f.Id
        | FaultRepeated (id, _)
        | FaultAcknowledged (id, _, _)
        | RecoveryStarted (id, _)
        | RecoveryConcluded (id, _, _, _)
        | FaultEscalated (id, _, _, _)
        | FaultResolved (id, _)
        | FaultReopened (id, _, _)
        | FaultSuperseded (id, _, _) -> Some id
        | ItemQuarantined item -> Some item.FaultId
        | ItemDeadLettered item -> Some item.FaultId
        | ItemReleased _
        | SinkFailed _ -> None
