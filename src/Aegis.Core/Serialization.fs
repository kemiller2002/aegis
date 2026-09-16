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
        | Diagnostic -> "Diagnostic"
        | Warning -> "Warning"
        | Error -> "Error"
        | Critical -> "Critical"

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
        | NoRecovery -> "NoRecovery"

    let eventTypeName =
        function
        | FaultRecorded _ -> "FaultRecorded"
        | FaultSuppressed _ -> "FaultSuppressed"
        | SinkFailed _ -> "SinkFailed"

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

    /// Serialize one event. `eventId` is distinct from the fault id, so all
    /// events for one fault can be reconstructed. Requirements: logging 13, 23, 24.
    let event (rules: Redaction.Rule list) (eventId: EventId) (ev: AegisEvent) =
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
            writer.WriteString("persistence", persistenceName fault.Persistence)
            writer.WriteString("recovery", recoveryName fault.Recovery)
            match fault.Owner with
            | Some o -> writer.WriteString("owner", o)
            | None -> ()
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

            match fault.Cause with
            | Some cause ->
                writer.WritePropertyName "cause"
                writeCause writer rules cause
            | None -> ()

        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.ToArray())
