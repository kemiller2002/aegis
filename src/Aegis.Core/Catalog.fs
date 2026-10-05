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

    let private guidance causes evidence checks prohibited transitions =
        { LikelyCauses = causes
          EvidenceToInspect = evidence
          SafeChecks = checks
          ProhibitedActions = prohibited
          ExpectedTransitions = transitions
          Documentation = None }

    /// Integrity and schema faults take their category and severity from the
    /// same mapping that raises them, so the catalog cannot drift from the
    /// code. None is eligible for retry or automatic recovery: correctness
    /// is not established, so nothing automatic may write. Requirement: core 20.
    let private integrity (failure: Integrity.IntegrityFailure) title description causes evidence =
        { Code = Integrity.mapping.Code failure
          Title = title
          Description = description
          Category = Integrity.mapping.Category failure
          DefaultSeverity = Integrity.mapping.Severity failure
          RetryEligible = false
          AutomaticRecoveryAllowed = false
          NotifyUser = true
          EscalationGuidance = Some "Keep the affected state read-only until a human has confirmed or repaired it."
          Guidance =
            guidance
                causes
                evidence
                [ "open the affected state read-only and compare it against history" ]
                [ Recovery.CanRetry; Recovery.CanReprocess ]
                [ "ReadOnly" ] }

    /// Configuration problems found at startup (`Bootstrap.describe`), which
    /// `Bootstrap.promote` raises as ConfigurationFailure warnings. They need
    /// a configuration change, never a retry.
    let private configuration code title description cause =
        { Code = FaultCode code
          Title = title
          Description = description
          Category = ConfigurationFailure
          DefaultSeverity = FaultSeverity.Warning
          RetryEligible = false
          AutomaticRecoveryAllowed = false
          NotifyUser = false
          EscalationGuidance = Some "Fix the configuration and restart; the condition will not clear by itself."
          Guidance =
            guidance
                [ cause ]
                [ "the bootstrap diagnostics promoted at startup"; "the Aegis configuration the host built" ]
                [ "run Bootstrap.validate against the configuration" ]
                [ Recovery.CanRetry; Recovery.CanReprocess ]
                [] }

    /// A starting catalog for every fault code this library itself raises.
    /// Complete by test: every `FaultCode "AEGIS.*"` literal in the shipped
    /// source must have an entry here.
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
        // ---------------------------------------------------------- network
        |> add
            { Code = FaultCode "AEGIS.NETWORK.TIMEOUT"
              Title = "Dependency timed out"
              Description = "A dependency did not respond within the allowed time. This is an infrastructure failure, not a cancellation."
              Category = InfrastructureFailure
              DefaultSeverity = FaultSeverity.Warning
              RetryEligible = true
              AutomaticRecoveryAllowed = true
              NotifyUser = false
              EscalationGuidance = Some "Escalate if timeouts persist beyond the transient window or retries are exhausted."
              Guidance =
                guidance
                    [ "the dependency is slow or overloaded"; "a network path is degraded"; "the configured timeout is too short for the workload" ]
                    [ "the configured timeout"; "occurrence count and consecutive failures"; "whether other dependencies also time out" ]
                    [ "retry once with backoff, only for an idempotent operation" ]
                    [ Recovery.CanQuarantine ]
                    [ "Offline"; "DegradedApplication" ] }
        // ----------------------------------------------------------- github
        |> add
            { Code = FaultCode "AEGIS.GITHUB.REPOSITORY_NOT_FOUND"
              Title = "GitHub repository not found"
              Description = "The configured repository does not exist, or the credentials cannot see it."
              Category = IntegrationFailure
              DefaultSeverity = FaultSeverity.Warning
              RetryEligible = false
              AutomaticRecoveryAllowed = false
              NotifyUser = true
              EscalationGuidance = Some "Needs a human to correct the repository identity or grant access."
              Guidance =
                guidance
                    [ "the repository was renamed, moved or deleted"; "the token cannot see a private repository" ]
                    [ "the configured owner and repository"; "the token's repository access" ]
                    [ "list repositories visible to the current credentials" ]
                    [ Recovery.CanRetry; Recovery.CanReprocess ]
                    [ "FeatureUnavailable" ] }
        |> add
            { Code = FaultCode "AEGIS.GITHUB.RATE_LIMITED"
              Title = "GitHub rate limit reached"
              Description = "GitHub refused the request because a rate limit was reached."
              Category = IntegrationFailure
              DefaultSeverity = FaultSeverity.Warning
              RetryEligible = true
              AutomaticRecoveryAllowed = true
              NotifyUser = true
              EscalationGuidance = Some "Escalate if the limit is reached repeatedly within one window."
              Guidance =
                guidance
                    [ "too many requests in the current window"; "a secondary rate limit on bursts of writes" ]
                    [ "the Retry-After and rate-limit headers"; "request volume per window" ]
                    [ "wait for the advertised reset before retrying" ]
                    [ Recovery.CanQuarantine ]
                    [ "DegradedApplication" ] }
        |> add
            { Code = FaultCode "AEGIS.GITHUB.CONFLICT"
              Title = "GitHub write conflict"
              Description = "The write conflicts with content already stored."
              Category = IntegrationFailure
              DefaultSeverity = FaultSeverity.Warning
              RetryEligible = false
              AutomaticRecoveryAllowed = false
              NotifyUser = true
              EscalationGuidance = Some "A conflict is never resolved by overwriting; a human decides."
              Guidance =
                guidance
                    [ "a concurrent writer changed the same path"; "a replay of different content under an existing id" ]
                    [ "the stored content at the conflicting path"; "the commit history for that path" ]
                    [ "read the stored content and compare it with the attempted write" ]
                    [ Recovery.CanRetry; Recovery.CanReprocess ]
                    [] }
        |> add
            { Code = FaultCode "AEGIS.GITHUB.INVALID_RESPONSE"
              Title = "GitHub response could not be used"
              Description = "GitHub returned a response that could not be read or was rejected, or an unrecognized failure occurred at the boundary."
              Category = IntegrationFailure
              DefaultSeverity = FaultSeverity.Error
              RetryEligible = false
              AutomaticRecoveryAllowed = false
              NotifyUser = true
              EscalationGuidance = Some "Escalate if it recurs; it may indicate an API change."
              Guidance =
                guidance
                    [ "an unexpected status or payload shape"; "an API change"; "an unrecognized exception at the integration boundary" ]
                    [ "the technical details and exception chain on the fault" ]
                    [ "repeat the request manually against the API, read-only" ]
                    [ Recovery.CanReprocess ]
                    [] }
        // ------------------------------------------------- integrity, schema
        |> add (
            integrity
                (Integrity.DeserializationFailed "")
                "Stored data could not be deserialized"
                "A stored payload could not be read at all, as distinct from one that needs migrating."
                [ "a truncated or corrupted write"; "a payload written by an incompatible tool" ]
                [ "the raw stored payload"; "the writer's version" ]
        )
        |> add (
            integrity
                (Integrity.InvalidPersistedState "")
                "Persisted state is invalid"
                "Stored state was read but violates its own invariants, so it cannot be trusted."
                [ "an interrupted multi-step write"; "manual edit of stored state" ]
                [ "the invariant that failed"; "the last successful write" ]
        )
        |> add (
            integrity
                (Integrity.MissingRequiredRelationship "")
                "Required related data is missing"
                "A stored record refers to related data that does not exist."
                [ "a partial delete"; "records written out of order" ]
                [ "the dangling reference"; "the history of the referenced record" ]
        )
        |> add (
            integrity
                (Integrity.UnexpectedRepositoryStructure "")
                "Repository structure is not as expected"
                "The storage layout does not match what this version expects."
                [ "a manual reorganisation"; "a different tool writing to the same location" ]
                [ "the actual layout"; "the expected layout for this version" ]
        )
        |> add (
            integrity
                (Integrity.Migration(Integrity.MigrationRequired("", "")))
                "Schema migration required"
                "Stored data is at an older schema version and must be migrated before it is written."
                [ "an upgrade that has not yet migrated stored data" ]
                [ "the stored and expected schema versions" ]
        )
        |> add (
            integrity
                (Integrity.Migration(Integrity.MigrationFailed ""))
                "Schema migration failed"
                "A migration was attempted and did not complete."
                [ "a migration defect"; "data the migration did not anticipate" ]
                [ "the migration log"; "the state before migration" ]
        )
        |> add (
            integrity
                (Integrity.Migration(Integrity.UnsupportedVersion ""))
                "Unsupported schema version"
                "Stored data is at a schema version this release cannot read."
                [ "data from a release too old to migrate directly" ]
                [ "the stored schema version"; "the supported range" ]
        )
        |> add (
            integrity
                (Integrity.Migration(Integrity.SchemaMismatch ""))
                "Schema mismatch"
                "Stored data does not match the schema it declares."
                [ "a writer that declared the wrong schema"; "manual edit" ]
                [ "the declared schema"; "the actual shape" ]
        )
        |> add (
            integrity
                (Integrity.Migration(Integrity.ForwardVersionUnsupported ""))
                "Stored data is from a newer version"
                "Stored data was written by a newer release; this release must not write over it."
                [ "a downgrade"; "two releases sharing one store" ]
                [ "the stored schema version"; "the running release" ]
        )
        |> add (
            integrity
                (Integrity.Migration(Integrity.BackwardCompatibilityViolation ""))
                "Backward compatibility violation"
                "A change would make stored data unreadable by releases that still rely on it."
                [ "a schema change without a compatible migration path" ]
                [ "the change and the releases that read this data" ]
        )
        // ----------------------------------------------------- configuration
        |> add (
            configuration
                "AEGIS.CONFIG.MISSING_APPLICATION"
                "Application name missing"
                "The Aegis configuration has no application name, so faults cannot be attributed."
                "the host did not pass an application name to Aegis.configure"
        )
        |> add (
            configuration
                "AEGIS.CONFIG.NO_SINKS"
                "No sinks configured"
                "The Aegis configuration declares no sinks, so no fault would be recorded anywhere."
                "the host configured Aegis with an empty sink list"
        )
        |> add (
            configuration
                "AEGIS.CONFIG.DUPLICATE_SINK"
                "Duplicate sink name"
                "More than one sink shares a name, so delivery reports and health are ambiguous."
                "the same sink was registered twice, or two sinks were given one name"
        )
        |> add (
            configuration
                "AEGIS.CONFIG.REQUIRED_SINK_NOT_DURABLE"
                "Required sink is not durable"
                "A sink declared Required does not support durable writes, so the requirement cannot be met."
                "a console or in-memory sink was marked Required"
        )
        |> add (
            configuration
                "AEGIS.CONFIG.UNNAMED_REDACTION_RULE"
                "Redaction rule has no name"
                "A redaction rule has no name, so its effect cannot be audited."
                "a custom redaction rule was added without a name"
        )
        |> add (
            configuration
                "AEGIS.CONFIG.INVALID_QUEUE_CAPACITY"
                "Invalid offline queue capacity"
                "The offline queue capacity is not positive, so deferred events could not be held."
                "a zero or negative capacity was configured"
        )
