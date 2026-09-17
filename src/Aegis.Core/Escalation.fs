namespace Aegis

open System

/// Escalation is policy-driven rather than hard-coded, and every escalation is
/// itself recorded so severity is never silently overwritten.
/// Requirements: additional 5, 35, 36.
module Escalation =

    /// Requirement: additional 5 -- the rule shapes the requirements name.
    type Rule =
        /// Warning becomes Error after repeated occurrence.
        | AfterOccurrences of count: int * target: FaultSeverity
        /// A fault still active after a window escalates.
        | AfterActiveFor of window: TimeSpan * target: FaultSeverity
        /// A transient fault becomes persistent after N minutes.
        | TransientBecomesPersistentAfter of window: TimeSpan

    type Policy = { Rules: Rule list }

    let none = { Rules = [] }

    let private severityRank =
        function
        | Diagnostic -> 0
        | Warning -> 1
        | FaultSeverity.Error -> 2
        | Critical -> 3

    /// Escalation only ever raises severity: a policy cannot quietly downgrade
    /// a fault. Requirement: additional 36.
    let private raises current target = severityRank target > severityRank current

    /// Evaluate a projected fault against the policy. Returns the escalation
    /// event to record, if any. Pure, so the same inputs always decide alike.
    let evaluate (policy: Policy) (now: DateTimeOffset) (projected: Lifecycle.Projected) =
        match projected.State with
        | Lifecycle.Resolved
        | Lifecycle.Superseded -> None
        | Lifecycle.Active
        | Lifecycle.AcknowledgedActive ->
            policy.Rules
            |> List.tryPick (fun rule ->
                match rule with
                | AfterOccurrences (count, target) when
                    projected.Occurrences >= count && raises projected.Severity target
                    ->
                    Some target
                | AfterActiveFor (window, target) when
                    now - projected.FirstSeen >= window && raises projected.Severity target
                    ->
                    Some target
                | _ -> None)
            |> Option.map (fun target -> FaultEscalated(projected.Fault.Id, projected.Severity, target, now))

    /// Whether a fault classified Transient has been failing long enough to be
    /// treated as Persistent. Requirement: additional 5.
    let reclassify (policy: Policy) (now: DateTimeOffset) (projected: Lifecycle.Projected) =
        match projected.Fault.Persistence with
        | Transient ->
            policy.Rules
            |> List.tryPick (function
                | TransientBecomesPersistentAfter window when now - projected.FirstSeen >= window -> Some Persistent
                | _ -> None)
        | _ -> None

    /// Faults sharing a dependency, so several visible application faults can
    /// be recognised as one underlying cause. The innermost shared dependency
    /// is the most specific explanation.
    /// Requirements: additional 45, 46.
    let byDependency (projection: Map<string, Lifecycle.Projected>) =
        projection
        |> Map.toList
        |> List.map snd
        |> List.collect (fun p -> p.Fault.Dependencies |> List.map (fun d -> d, p))
        |> List.groupBy fst
        |> List.map (fun (dependency, entries) -> dependency, entries |> List.map snd)
        |> Map.ofList

    /// The dependency shared by the most active faults: the likeliest single
    /// root cause behind several symptoms. Requirement: additional 46.
    let likelyRootCause (projection: Map<string, Lifecycle.Projected>) =
        let active = Lifecycle.active projection |> List.map (fun p -> p.Fault.Id.Value) |> Set.ofList

        byDependency projection
        |> Map.toList
        |> List.map (fun (dependency, faults) ->
            dependency, faults |> List.filter (fun p -> active.Contains p.Fault.Id.Value))
        |> List.filter (fun (_, faults) -> List.length faults > 1)
        // Prefer the dependency implicated by most faults; on a tie prefer the
        // innermost, which appears later in every chain.
        |> List.sortByDescending (fun (dependency, faults) ->
            List.length faults,
            faults
            |> List.map (fun p -> p.Fault.Dependencies |> List.findIndex (fun d -> d = dependency))
            |> List.max)
        |> List.tryHead
