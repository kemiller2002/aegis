namespace Aegis

open System

/// Translation from an integration assembly's typed failure model into the
/// shared fault model.
///
/// The responsibility split the requirements set out: the integration assembly
/// knows WHAT failed, Aegis knows HOW the fault is represented and handled.
/// So translation is parameterised over the assembly's own failure type rather
/// than Aegis knowing about any particular technology.
/// Requirements: core 16, 17, 32; additional 24.
module Translation =

    /// How one typed integration failure maps onto fault attributes. The
    /// integration assembly supplies this; Aegis normalizes the result.
    /// Requirement: core 32.
    type Mapping<'failure> =
        { Code: 'failure -> FaultCode
          Category: 'failure -> FailureCategory
          Severity: 'failure -> FaultSeverity
          Impact: 'failure -> FaultImpact
          Persistence: 'failure -> Persistence
          Recovery: 'failure -> RecoveryPolicy
          UserMessage: 'failure -> string
          Owner: string }

    /// Normalize a typed integration failure into a fault, preserving the
    /// original exception detail where one exists so translation never
    /// destroys diagnostics. Requirement: core 17.
    let toFault
        (mapping: Mapping<'failure>)
        (identity: FaultId * CorrelationId * DateTimeOffset)
        (application: string, version: string option)
        (operation: string)
        (context: Map<string, ContextValue>)
        (cause: FaultCause option)
        (failure: 'failure)
        =
        let id, correlationId, at = identity

        { Id = id
          CorrelationId = correlationId
          Timestamp = at
          Application = application
          ApplicationVersion = version
          Operation = operation
          Category = mapping.Category failure
          Code = mapping.Code failure
          Severity = mapping.Severity failure
          Impact = mapping.Impact failure
          Persistence = mapping.Persistence failure
          Owner = Some mapping.Owner
          UserMessage = mapping.UserMessage failure
          TechnicalDetails = Some(string (box failure))
          Context = context
          Recovery = mapping.Recovery failure
          Cause = cause }

/// Data integrity and schema migration failures, which the requirements
/// single out for treatment distinct from a generic deserialization error.
/// Requirements: core 20; additional 24.
module Integrity =

    /// Requirement: additional 24 -- migration failures must be
    /// distinguishable from ordinary deserialization failures, because the
    /// recovery is completely different.
    type MigrationFailure =
        | MigrationRequired of from: string * target: string
        | MigrationFailed of reason: string
        | UnsupportedVersion of found: string
        | SchemaMismatch of detail: string
        | ForwardVersionUnsupported of found: string
        | BackwardCompatibilityViolation of detail: string

    /// Requirement: core 20.
    type IntegrityFailure =
        | InvalidPersistedState of detail: string
        | MissingRequiredRelationship of detail: string
        | HashMismatch of expected: string * actual: string
        | UnexpectedRepositoryStructure of detail: string
        | Migration of MigrationFailure

    let code =
        function
        | InvalidPersistedState _ -> FaultCode "AEGIS.DATA.INVALID_PERSISTED_STATE"
        | MissingRequiredRelationship _ -> FaultCode "AEGIS.DATA.MISSING_RELATIONSHIP"
        | HashMismatch _ -> FaultCode "AEGIS.DATA.HASH_MISMATCH"
        | UnexpectedRepositoryStructure _ -> FaultCode "AEGIS.DATA.UNEXPECTED_STRUCTURE"
        | Migration (MigrationRequired _) -> FaultCode "AEGIS.SCHEMA.MIGRATION_REQUIRED"
        | Migration (MigrationFailed _) -> FaultCode "AEGIS.SCHEMA.MIGRATION_FAILED"
        | Migration (UnsupportedVersion _) -> FaultCode "AEGIS.SCHEMA.UNSUPPORTED_VERSION"
        | Migration (SchemaMismatch _) -> FaultCode "AEGIS.SCHEMA.MISMATCH"
        | Migration (ForwardVersionUnsupported _) -> FaultCode "AEGIS.SCHEMA.FORWARD_VERSION_UNSUPPORTED"
        | Migration (BackwardCompatibilityViolation _) -> FaultCode "AEGIS.SCHEMA.BACKWARD_COMPATIBILITY_VIOLATION"

    /// Integrity recovery must not mutate data before correctness is
    /// established, so nothing here proposes a write. Requirement: core 20.
    let recovery =
        function
        | InvalidPersistedState _
        | UnexpectedRepositoryStructure _
        | HashMismatch _ -> ReadOnlyRecovery
        | MissingRequiredRelationship _ -> ManualIntervention
        | Migration (MigrationRequired _) -> ReadOnlyRecovery
        | Migration (UnsupportedVersion _)
        | Migration (ForwardVersionUnsupported _) -> ReadOnlyRecovery
        | Migration (MigrationFailed _)
        | Migration (SchemaMismatch _)
        | Migration (BackwardCompatibilityViolation _) -> ManualIntervention

    /// Integrity faults threaten correctness, so they are never merely
    /// operational. Requirements: core 20, 39.
    let impact =
        function
        | HashMismatch _
        | InvalidPersistedState _ -> ApplicationUnsafe
        | UnexpectedRepositoryStructure _
        | MissingRequiredRelationship _ -> DegradedApplication
        | Migration _ -> FeatureUnavailable

    let mapping: Translation.Mapping<IntegrityFailure> =
        { Code = code
          Category = fun _ -> DataFailure
          Severity = fun f -> if impact f = ApplicationUnsafe then Critical else FaultSeverity.Error
          Impact = impact
          Persistence = fun _ -> RequiresIntervention
          Recovery = recovery
          UserMessage = fun _ -> "Stored data could not be read safely."
          Owner = "Aegis" }
