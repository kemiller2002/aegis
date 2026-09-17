namespace Aegis

open System

/// Aegis's view of its own operational health, derived from observed sink
/// outcomes and queue depth rather than from hidden counters.
/// Consumed by SDE and Limen. Requirements: additional 51; logging 38.
module Health =

    /// The states the requirements enumerate. Requirement: additional 51.
    type State =
        | Healthy
        | Degraded
        | PersistenceUnavailable
        | QueueBacklogged
        | BootstrapOnly
        | CriticalFailure

    type Projection =
        { State: State
          Sinks: Map<string, Sinks.Health>
          Queued: int
          /// True until initialization completes, when only bootstrap
          /// diagnostics are available. Requirement: additional 20.
          InBootstrap: bool }

    /// Derive the projection. Ordering matters: bootstrap wins because
    /// nothing else is trustworthy yet, and a failed required sink is
    /// critical because the application's operating mode depends on it
    /// (additional 50).
    let project (inBootstrap: bool) (backlogThreshold: int) (queued: int) (sinks: Map<string, Sinks.Health>) =
        let byState predicate =
            sinks |> Map.toList |> List.map snd |> List.filter predicate

        let unavailable = byState (fun h -> h.State = Sinks.SinkUnavailable)
        let degraded = byState (fun h -> h.State = Sinks.SinkDegraded)

        let requiredBroken =
            unavailable @ degraded |> List.exists (fun h -> h.Level = Sinks.Required)

        let state =
            if inBootstrap then BootstrapOnly
            elif requiredBroken then CriticalFailure
            elif not (List.isEmpty unavailable) && List.isEmpty (byState (fun h -> h.State = Sinks.Available)) then
                PersistenceUnavailable
            elif queued > backlogThreshold then QueueBacklogged
            elif not (List.isEmpty unavailable) || not (List.isEmpty degraded) then Degraded
            else Healthy

        { State = state
          Sinks = sinks
          Queued = queued
          InBootstrap = inBootstrap }

    /// Whether the application should be told to stop relying on diagnostics
    /// being durable. Requirement: logging 44.
    let persistenceTrustworthy (projection: Projection) =
        match projection.State with
        | Healthy
        | QueueBacklogged -> true
        | Degraded
        | PersistenceUnavailable
        | BootstrapOnly
        | CriticalFailure -> false
