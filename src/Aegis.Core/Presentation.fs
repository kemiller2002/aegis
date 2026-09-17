namespace Aegis

open System

/// What a fault looks like to a person, expressed as intent and structure.
/// Aegis never renders anything: Limen decides how this is shown.
/// Requirements: core 10, 11; additional 25, 26; logging 45.
module Presentation =

    /// Requirement: additional 25 -- intent, not rendering.
    type Intent =
        | Silent
        | Inline
        | Notification
        | Banner
        | Blocking

    /// An offered recovery, named for a person but tied to a capability the
    /// machine can check. Requirements: core 10; additional 28.
    type Action =
        { Label: string
          Capability: Recovery.Capability }

    /// The presentation model Limen consumes. Requirement: core 10.
    type T =
        { Title: string
          Message: string
          Severity: FaultSeverity
          Intent: Intent
          Actions: Action list
          /// Short reference a person can quote back. Requirement: core 31.
          Reference: string }

    /// Not every persisted fault deserves a visible notification.
    /// Requirement: additional 25.
    let intentFor (fault: Fault) =
        match fault.Severity, fault.Impact with
        | Diagnostic, _ -> Silent
        | _, ApplicationUnsafe -> Blocking
        | Critical, _ -> Banner
        | _, DegradedApplication -> Banner
        | _, FeatureUnavailable -> Notification
        | _, OperationOnly -> Inline

    let private label =
        function
        | Recovery.CanRetry -> "Try again"
        | Recovery.CanReauthenticate -> "Sign in"
        | Recovery.CanReload -> "Reload"
        | Recovery.CanQuarantine -> "Set aside"
        | Recovery.CanReprocess -> "Process again"
        | Recovery.CanOpenReadOnly -> "Open read-only"
        | Recovery.CanRestoreSink -> "Reconnect diagnostics"

    /// A short quotable reference derived from the fault id, not the message.
    let reference (fault: Fault) =
        let id = fault.Id.Value
        let tail = if id.Length <= 5 then id else id.Substring(id.Length - 5)
        $"AG-{tail}"

    /// Build the presentation. Only the user-facing message is used, so no
    /// stack trace, token or internal path can reach a person.
    /// Requirement: core 11.
    let present (title: string) (fault: Fault) =
        { Title = title
          Message = fault.UserMessage
          Severity = fault.Severity
          Intent = intentFor fault
          Actions = Recovery.capabilities fault |> List.map (fun c -> { Label = label c; Capability = c })
          Reference = reference fault }

    /// Notification throttling: many occurrences, one visible notification,
    /// while diagnostic fidelity is untouched. Requirement: additional 26.
    type Throttle =
        { Window: TimeSpan
          LastNotified: Map<string, DateTimeOffset> }

    let throttle window =
        { Window = window
          LastNotified = Map.empty }

    /// Decide whether this fault should notify now, keyed by fingerprint so
    /// repeats of one underlying problem collapse. Returns the decision and
    /// the updated throttle, leaving the caller's state explicit.
    let shouldNotify (now: DateTimeOffset) (fault: Fault) (state: Throttle) =
        let key = (Lifecycle.fingerprint fault).Value

        match intentFor fault with
        | Silent -> false, state
        | _ ->
            match Map.tryFind key state.LastNotified with
            | Some last when now - last < state.Window -> false, state
            | _ -> true, { state with LastNotified = Map.add key now state.LastNotified }

    /// Diagnostic persistence state for Limen to render. Aegis supplies the
    /// state; Limen chooses the words. Requirement: logging 45.
    type PersistenceState =
        | Synchronized
        | Queued of pending: int
        | Unavailable
        | LastSynchronizationFailed of reason: string

    let persistenceState (queue: Offline.Queue) (lastFailure: string option) (sinkHealthy: bool) =
        match sinkHealthy, Offline.count queue, lastFailure with
        | false, _, Some reason -> LastSynchronizationFailed reason
        | false, _, None -> Unavailable
        | true, 0, _ -> Synchronized
        | true, pending, _ -> Queued pending
