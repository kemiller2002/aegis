namespace Aegis

open System
open System.Text
open System.Text.Json

/// Serialization to the storage-independent event shape. Redaction is applied
/// here, before any sink sees the payload.
/// Requirements: core 37; additional 40; logging 11, 12, 13, 21, 25.
module Serialization =

    let private categoryName =
        function
        | DomainFailure -> "DomainFailure"
        | InfrastructureFailure -> "InfrastructureFailure"
        | IntegrationFailure -> "IntegrationFailure"
        | DataFailure -> "DataFailure"
        | ConfigurationFailure -> "ConfigurationFailure"
        | SecurityFailure -> "SecurityFailure"
        | ProgrammingDefect -> "ProgrammingDefect"
        | UnknownFailure -> "UnknownFailure"

    let private severityName =
        function
        | FaultSeverity.Diagnostic -> "Diagnostic"
        | FaultSeverity.Warning -> "Warning"
        | FaultSeverity.Error -> "Error"
        | FaultSeverity.Critical -> "Critical"

    let private impactName =
        function
        | OperationOnly -> "OperationOnly"
        | FeatureUnavailable -> "FeatureUnavailable"
        | DegradedApplication -> "DegradedApplication"
        | ApplicationUnsafe -> "ApplicationUnsafe"

    let private persistenceName =
        function
        | Transient -> "Transient"
        | Persistent -> "Persistent"
        | Permanent -> "Permanent"
        | UnknownPersistence -> "Unknown"
        | RequiresIntervention -> "RequiresIntervention"

    let private recoveryName =
        function
        | Retry (attempts, _) -> $"Retry({attempts})"
        | Reauthenticate -> "Reauthenticate"
        | Reload -> "Reload"
        | Refresh -> "Refresh"
        | Continue -> "Continue"
        | AbortOperation -> "AbortOperation"
        | RestartApplication -> "RestartApplication"
        | ManualIntervention -> "ManualIntervention"
        | ReadOnlyRecovery -> "ReadOnlyRecovery"
        | NoRecovery -> "NoRecovery"

    let eventTypeName =
        function
        | FaultRecorded _ -> "FaultRecorded"
        | FaultSuppressed _ -> "FaultSuppressed"
        | FaultRepeated _ -> "FaultRepeated"
        | FaultAcknowledged _ -> "FaultAcknowledged"
        | RecoveryStarted _ -> "RecoveryStarted"
        | RecoveryConcluded _ -> "RecoveryConcluded"
        | FaultEscalated _ -> "FaultEscalated"
        | FaultResolved _ -> "FaultResolved"
        | FaultReopened _ -> "FaultReopened"
        | FaultSuperseded _ -> "FaultSuperseded"
        | ItemQuarantined _ -> "ItemQuarantined"
        | ItemReleased _ -> "ItemReleased"
        | ItemDeadLettered _ -> "ItemDeadLettered"
        | SinkFailed _ -> "SinkFailed"

    let private actorName =
        function
        | User -> "User"
        | Application -> "Application"
        | Agent -> "Agent"
        | ScheduledProcess -> "ScheduledProcess"
        | Integration -> "Integration"
        | Operator -> "Operator"

    let private outcomeName =
        function
        | Succeeded -> "Succeeded"
        | FailedWith _ -> "Failed"
        | AwaitingVerification -> "AwaitingVerification"

    let private resolutionKindName =
        function
        | ResolvedAutomatically -> "Automatic"
        | ResolvedManually -> "Manual"
        | NoLongerApplies -> "NoLongerApplies"

    let private domainName =
        function
        | LocalOperation -> "LocalOperation"
        | FeatureDomain -> "Feature"
        | IntegrationDomain -> "Integration"
        | RepositoryDomain -> "Repository"
        | ApplicationDomain -> "Application"
        | EnvironmentDomain -> "Environment"
        | ExternalDependency -> "ExternalDependency"

    let private radiusName =
        function
        | OneItem -> "OneItem"
        | OneOperation -> "OneOperation"
        | OneFeature -> "OneFeature"
        | OneRepository -> "OneRepository"
        | OneSession -> "OneSession"
        | EntireApplication -> "EntireApplication"

    let private retentionName =
        function
        | RetainIndefinitely -> "RetainIndefinitely"
        | RetainDays days -> $"RetainDays({days})"
        | ArchiveAfterDays days -> $"ArchiveAfterDays({days})"
        | DiagnosticOnly -> "DiagnosticOnly"
        | AuditRequired -> "AuditRequired"

    /// UTC is canonical. Requirement: logging 25.
    let private timestamp (t: DateTimeOffset) =
        t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    let rec private writeCause (w: Utf8JsonWriter) rules cause =
        match cause with
        | CausedByException detail ->
            w.WriteStartObject()
            w.WriteString("kind", "exception")
            w.WriteString("exceptionType", detail.ExceptionType)
            w.WriteString("message", detail.Message)
            match detail.Inner with
            | Some inner ->
                w.WritePropertyName "inner"
                writeCause w rules (CausedByException inner)
            | None -> ()
            w.WriteEndObject()
        | CausedByFault f ->
            w.WriteStartObject()
            w.WriteString("kind", "fault")
            w.WriteString("faultId", f.Id.Value)
            w.WriteString("code", f.Code.Value)
            match f.Cause with
            | Some inner ->
                w.WritePropertyName "cause"
                writeCause w rules inner
            | None -> ()
            w.WriteEndObject()

    /// The one event writer behind `event` and `attributedEvent`.
    let private write (rules: Redaction.Rule list) (eventId: EventId) (ev: AegisEvent) (provenance: ProvenanceBlock option) =
        use stream = new IO.MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("schema", Schema.Event)
        writer.WriteString("eventId", eventId.Value)
        writer.WriteString("eventType", eventTypeName ev)

        match ev with
        | SinkFailed (sinkName, code, message) ->
            writer.WriteString("sink", sinkName)
            writer.WriteString("code", code.Value)
            writer.WriteString("message", message)
        | FaultRecorded fault
        | FaultSuppressed (fault, _) ->
            writer.WriteString("faultId", fault.Id.Value)
            writer.WriteString("correlationId", fault.CorrelationId.Value)
            writer.WriteString("timestamp", timestamp fault.Timestamp)
            writer.WriteString("application", fault.Application)
            match fault.ApplicationVersion with
            | Some v -> writer.WriteString("applicationVersion", v)
            | None -> ()
            writer.WriteString("operation", fault.Operation)
            writer.WriteString("code", fault.Code.Value)
            writer.WriteString("category", categoryName fault.Category)
            writer.WriteString("severity", severityName fault.Severity)
            writer.WriteString("impact", impactName fault.Impact)
            writer.WriteString("domain", domainName fault.Domain)
            writer.WriteString("radius", radiusName fault.Radius)
            writer.WriteString("retention", retentionName fault.Retention)
            writer.WriteString("persistence", persistenceName fault.Persistence)
            writer.WriteString("recovery", recoveryName fault.Recovery)
            match fault.Owner with
            | Some o -> writer.WriteString("owner", o)
            | None -> ()

            match fault.Dependencies with
            | [] -> ()
            | chain ->
                writer.WritePropertyName "dependencies"
                writer.WriteStartArray()
                for dependency in chain do
                    writer.WriteStringValue dependency
                writer.WriteEndArray()
            writer.WriteString("userMessage", fault.UserMessage)
            match fault.TechnicalDetails with
            | Some d -> writer.WriteString("technicalDetails", d)
            | None -> ()

            match ev with
            | FaultSuppressed (_, reason) -> writer.WriteString("suppressionReason", reason)
            | _ -> ()

            writer.WritePropertyName "context"
            writer.WriteStartObject()
            for KeyValue (key, value) in Redaction.apply rules fault.Context do
                writer.WriteString(key, value)
            writer.WriteEndObject()

            match Redaction.audit rules fault.Context with
            | [] -> ()
            | entries ->
                writer.WritePropertyName "redacted"
                writer.WriteStartObject()
                for key, reason in entries do
                    writer.WriteString(key, reason)
                writer.WriteEndObject()

            match fault.Diagnostics.Environment with
            | Some env ->
                writer.WritePropertyName "environment"
                writer.WriteStartObject()
                for key, value in
                    [ "applicationVersion", env.ApplicationVersion
                      "buildVersion", env.BuildVersion
                      "commitSha", env.CommitSha
                      "branch", env.Branch
                      "deploymentEnvironment", env.DeploymentEnvironment
                      "runtimeVersion", env.RuntimeVersion
                      "operatingSystem", env.OperatingSystem
                      "browserVersion", env.BrowserVersion
                      "schemaVersion", env.SchemaVersion ] do
                    match value with
                    | Some v -> writer.WriteString(key, v)
                    | None -> ()

                for KeyValue (name, version) in env.ComponentVersions do
                    writer.WriteString(name, version)

                writer.WriteEndObject()
            | None -> ()

            match fault.Diagnostics.Snapshot with
            | Some snapshot ->
                // A reference, never the state itself. Requirement: additional 12.
                writer.WritePropertyName "snapshot"
                writer.WriteStartObject()
                writer.WriteString("location", snapshot.Location)
                writer.WriteString("digest", snapshot.Digest)
                writer.WriteString("summary", snapshot.Summary)
                writer.WriteString("capturedAt", timestamp snapshot.CapturedAt)
                writer.WriteEndObject()
            | None -> ()

            match fault.Diagnostics.Breadcrumbs with
            | [] -> ()
            | crumbs ->
                writer.WritePropertyName "breadcrumbs"
                writer.WriteStartArray()

                for crumb in crumbs do
                    writer.WriteStartObject()
                    writer.WriteString("at", timestamp crumb.At)
                    writer.WriteString("category", crumb.Category)
                    writer.WriteString("message", crumb.Message)

                    match Map.toList crumb.Data with
                    | [] -> ()
                    | _ ->
                        // Breadcrumb data is context and is redacted as such.
                        // Requirement: logging 21.
                        writer.WritePropertyName "data"
                        writer.WriteStartObject()

                        for KeyValue (key, value) in Redaction.apply rules crumb.Data do
                            writer.WriteString(key, value)

                        writer.WriteEndObject()

                    writer.WriteEndObject()

                writer.WriteEndArray()

            match fault.Cause with
            | Some cause ->
                writer.WritePropertyName "cause"
                writeCause writer rules cause
            | None -> ()

        // Lifecycle events reference the fault by id rather than repeating the
        // whole record, so history stays append-oriented and compact.
        // Requirements: logging 23; additional 30.
        | FaultRepeated (id, at) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteString("timestamp", timestamp at)
        | FaultAcknowledged (id, actor, at) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteString("acknowledgedBy", actorName actor)
            writer.WriteString("timestamp", timestamp at)
        | RecoveryStarted (id, attempt) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteString("correlationId", attempt.CorrelationId.Value)
            writer.WriteString("timestamp", timestamp attempt.Timestamp)
            writer.WriteString("recoveryAction", recoveryName attempt.Action)
            writer.WriteNumber("attemptNumber", attempt.AttemptNumber)
            writer.WriteString("actor", actorName attempt.Actor)
            writer.WriteString("outcome", outcomeName attempt.Outcome)
        | RecoveryConcluded (id, attemptNumber, outcome, at) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteNumber("attemptNumber", attemptNumber)
            writer.WriteString("outcome", outcomeName outcome)
            writer.WriteString("timestamp", timestamp at)
            match outcome with
            | FailedWith reason -> writer.WriteString("reason", reason)
            | Succeeded
            | AwaitingVerification -> ()
        | FaultEscalated (id, previous, current, at) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteString("previousSeverity", severityName previous)
            writer.WriteString("severity", severityName current)
            writer.WriteString("timestamp", timestamp at)
        | FaultResolved (id, resolution) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteString("resolutionKind", resolutionKindName resolution.Kind)
            writer.WriteBoolean("verified", resolution.Verified)
            writer.WriteString("timestamp", timestamp resolution.Timestamp)
            match resolution.Action with
            | Some action -> writer.WriteString("recoveryAction", recoveryName action)
            | None -> ()
        | FaultReopened (id, at, reason) ->
            writer.WriteString("faultId", id.Value)
            writer.WriteString("reason", reason)
            writer.WriteString("timestamp", timestamp at)
        | FaultSuperseded (superseded, by, at) ->
            writer.WriteString("faultId", superseded.Value)
            writer.WriteString("supersededBy", by.Value)
            writer.WriteString("timestamp", timestamp at)
        | ItemQuarantined item ->
            // A reference, never the payload. Requirement: additional 7.
            writer.WriteString("faultId", item.FaultId.Value)
            writer.WriteString("code", item.Code.Value)
            writer.WriteString("sourceId", item.SourceId)
            writer.WriteString("payloadReference", item.PayloadReference)
            writer.WriteString("reason", item.Reason)
            writer.WriteBoolean("retryEligible", item.RetryEligible)
            writer.WriteString("timestamp", timestamp item.At)
            // Quarantined data is held for investigation, so it is audit
            // material rather than disposable. Requirement: logging 26.
            writer.WriteString("retention", retentionName AuditRequired)
        | ItemReleased (sourceId, at) ->
            writer.WriteString("sourceId", sourceId)
            writer.WriteString("timestamp", timestamp at)
        | ItemDeadLettered item ->
            writer.WriteString("faultId", item.FaultId.Value)
            writer.WriteString("code", item.Code.Value)
            writer.WriteString("itemId", item.ItemId)
            writer.WriteString("payloadReference", item.PayloadReference)
            writer.WriteString("finalReason", item.FinalReason)
            writer.WriteNumber("attempts", List.length item.Attempts)
            writer.WriteBoolean("requiresManualIntervention", item.RequiresManualIntervention)
            writer.WriteBoolean("reprocessable", item.Reprocessable)
            writer.WriteString("timestamp", timestamp item.At)
            writer.WriteString("retention", retentionName AuditRequired)

        // Contribution provenance is written verbatim: unknown fields and
        // other majors survive untouched. A ProvenanceBlock cannot be
        // malformed, so nothing unvalidated reaches a sink. An event without
        // one is exactly what it was before provenance existed.
        // Requirements: AEG-PROV-001, AEG-PROV-007, AEG-PROV-008.
        match provenance with
        | Some block ->
            writer.WritePropertyName "provenance"
            writer.WriteRawValue block.Json
        | None -> ()

        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.ToArray())

    /// Serialize one event. `eventId` is distinct from the fault id, so all
    /// events for one fault can be reconstructed. Requirements: logging 13, 23, 24.
    let event (rules: Redaction.Rule list) (eventId: EventId) (ev: AegisEvent) = write rules eventId ev None

    /// Serialize one event with the contribution provenance of the act it
    /// records, under the `provenance` field. Requirement: AEG-PROV-001.
    let attributedEvent (rules: Redaction.Rule list) (eventId: EventId) (attributed: AttributedEvent) =
        write rules eventId attributed.Event attributed.Provenance

    /// Serialize a fault on its own, carrying the fault schema version so
    /// future tooling never depends implicitly on the current shape.
    /// Requirement: core 37.
    let private faultWith (rules: Redaction.Rule list) (f: Fault) (provenance: ProvenanceBlock option) =
        let asEvent = write rules (EventId f.Id.Value) (FaultRecorded f) provenance
        // Reuse the event shape's field layout, restamped with the fault
        // schema and without the event-only identifiers.
        asEvent
            .Replace($"\"schema\":\"{Schema.Event}\"", $"\"schema\":\"{Schema.Fault}\"")
            .Replace($"\"eventId\":\"{f.Id.Value}\",", "")
            .Replace("\"eventType\":\"FaultRecorded\",", "")

    /// Serialize a fault on its own. Requirement: core 37.
    let fault (rules: Redaction.Rule list) (f: Fault) = faultWith rules f None

    /// Serialize a fault with its discovering (or accumulated) contribution
    /// provenance. Requirement: AEG-PROV-001.
    let attributedFault (rules: Redaction.Rule list) (f: Fault) (provenance: ProvenanceBlock) =
        faultWith rules f (Some provenance)
