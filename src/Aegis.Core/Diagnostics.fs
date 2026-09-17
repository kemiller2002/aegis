namespace Aegis

open System

/// The operator- and agent-facing diagnostic layer: what led up to a fault,
/// what the environment was, and how to export that safely.
/// Requirements: additional 2, 10, 11, 12, 13, 40.
module Diagnostics =

    /// Bounded: breadcrumb history must not grow without limit.
    /// Requirement: additional 2.
    type Trail =
        { Entries: Breadcrumb list
          Capacity: int
          Dropped: int }

    let trail capacity =
        { Entries = []
          Capacity = max 1 capacity
          Dropped = 0 }

    let leave (crumb: Breadcrumb) (t: Trail) =
        let appended = t.Entries @ [ crumb ]

        if List.length appended <= t.Capacity then
            { t with Entries = appended }
        else
            { t with
                Entries = List.tail appended
                Dropped = t.Dropped + 1 }

    let crumb at category message data =
        { At = at
          Category = category
          Message = message
          Data = data }

    /// The most recent crumbs, oldest first, for attaching to a fault.
    let recent count (t: Trail) =
        let entries = t.Entries
        let skip = max 0 (List.length entries - count)
        entries |> List.skip skip

    /// Enough to answer "did this start after commit X" and "which build
    /// produced this". Requirement: additional 11.
    let deploymentIdentity (env: EnvironmentInfo) =
        [ "commit", env.CommitSha
          "build", env.BuildVersion
          "branch", env.Branch
          "environment", env.DeploymentEnvironment ]
        |> List.choose (fun (key, value) -> value |> Option.map (fun v -> key, v))
        |> Map.ofList

    /// Attach the most recent crumbs, and any environment or snapshot
    /// material, to a fault. This is what makes additional 2, 10, 11 and 12
    /// more than type definitions.
    let attach (count: int) (trail: Trail) (environment: EnvironmentInfo option) (snapshot: SnapshotReference option) (fault: Fault) =
        { fault with
            Diagnostics =
                { Breadcrumbs = recent count trail
                  Environment = environment
                  Snapshot = snapshot } }

    /// A portable, machine-readable bundle for human or agent analysis.
    /// Requirement: additional 13.
    type Bundle =
        { GeneratedAt: DateTimeOffset
          Application: string
          Environment: EnvironmentInfo
          Faults: Fault list
          Breadcrumbs: Breadcrumb list
          Snapshots: SnapshotReference list
          /// Configuration metadata with secrets already removed.
          Configuration: Map<string, string>
          SinkHealth: Map<string, string>
          RecoveryAttempts: RecoveryAttempt list }

    /// Export applies redaction after all aggregation and immediately before
    /// output, so a bundle can never become a way around sink redaction.
    /// Requirement: additional 40.
    let export (rules: Redaction.Rule list) (bundle: Bundle) =
        let redactedFaults =
            bundle.Faults
            |> List.map (fun fault ->
                { fault with
                    Context =
                        Redaction.apply rules fault.Context
                        |> Map.map (fun _ value -> Public value)
                    // Technical detail is for developers, not for export.
                    TechnicalDetails = None })

        let redactedCrumbs =
            bundle.Breadcrumbs
            |> List.map (fun crumb ->
                { crumb with
                    Data =
                        Redaction.apply rules crumb.Data
                        |> Map.map (fun _ value -> Public value) })

        let redactedConfiguration =
            bundle.Configuration
            |> Map.map (fun key value -> Public value)
            |> Redaction.apply rules

        { bundle with
            Faults = redactedFaults
            Breadcrumbs = redactedCrumbs
            Configuration = redactedConfiguration }

    /// Whether anything in a bundle still carries a value that should have
    /// been removed. A redacted entry keeps its key with the placeholder --
    /// the same shape a sink receives, so a reader can see something was
    /// removed -- so a surviving *value* is what counts as a leak, not a
    /// surviving key. Requirement: additional 40.
    let leaks (rules: Redaction.Rule list) (bundle: Bundle) =
        let offending (context: Map<string, ContextValue>) =
            context
            |> Map.toList
            |> List.choose (fun (key, value) ->
                match Redaction.decide rules key value with
                | Redaction.Kept _ -> None
                | Redaction.Masked _
                | Redaction.Dropped _ ->
                    if value.Raw = Redaction.Placeholder then None else Some(key, value.Raw))

        let fromFaults = bundle.Faults |> List.collect (fun f -> offending f.Context)
        let fromCrumbs = bundle.Breadcrumbs |> List.collect (fun c -> offending c.Data)

        let fromConfig =
            bundle.Configuration |> Map.map (fun _ v -> Public v) |> offending

        fromFaults @ fromCrumbs @ fromConfig
