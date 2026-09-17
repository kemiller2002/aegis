namespace Aegis

open System

/// The edges of an application's life: validating configuration before it is
/// trusted, reporting faults before full state exists, and reporting failures
/// during controlled shutdown.
/// Requirements: additional 20, 21, 47.
module Bootstrap =

    /// Configuration problems are values, not exceptions: validation must never
    /// itself trigger a recursive Aegis initialization failure.
    /// Requirement: additional 47.
    type ConfigProblem =
        | MissingApplicationName
        | NoSinksConfigured
        | DuplicateSinkName of string
        | RequiredSinkWithoutDurableWrite of string
        | RedactionRuleWithoutName
        | InvalidQueueCapacity of int

    let private duplicates names =
        names
        |> List.countBy id
        |> List.filter (fun (_, count) -> count > 1)
        |> List.map fst

    /// Validate without side effects. Returns every problem found rather than
    /// failing on the first, so one startup pass reports the whole picture.
    /// Requirement: additional 47.
    let validate (queueCapacity: int option) (config: AegisConfig) =
        let problems =
            [ if String.IsNullOrWhiteSpace config.Application then
                  MissingApplicationName

              if List.isEmpty config.Sinks then
                  NoSinksConfigured

              yield!
                  config.Sinks
                  |> List.map (fun s -> s.Name)
                  |> duplicates
                  |> List.map DuplicateSinkName

              // A sink the application depends on must actually claim durable
              // writes, or "required" means nothing. Requirement: additional 48, 50.
              yield!
                  config.Sinks
                  |> List.filter (fun s ->
                      s.Level = Sinks.Required
                      && not (s.Capabilities |> List.contains Sinks.SupportsDurableWrite))
                  |> List.map (fun s -> RequiredSinkWithoutDurableWrite s.Name)

              if config.Rules |> List.exists (fun r -> String.IsNullOrWhiteSpace r.Name) then
                  RedactionRuleWithoutName

              match queueCapacity with
              | Some capacity when capacity <= 0 -> InvalidQueueCapacity capacity
              | _ -> () ]

        if List.isEmpty problems then Ok config else Result.Error problems

    /// Diagnostics gathered before sinks are available. Bounded, because a
    /// failing startup must not exhaust memory. Requirement: additional 20.
    type Pending =
        { Entries: (DateTimeOffset * FaultCode * string) list
          Capacity: int
          Dropped: int }

    let minimal capacity =
        { Entries = []
          Capacity = max 1 capacity
          Dropped = 0 }

    /// Record a startup diagnostic. Never throws: at this point there may be
    /// no sink, no state and no configuration to fall back on.
    let record (at: DateTimeOffset) (code: FaultCode) (message: string) (pending: Pending) =
        let appended = pending.Entries @ [ at, code, message ]

        if List.length appended <= pending.Capacity then
            { pending with Entries = appended }
        else
            { pending with
                Entries = List.tail appended
                Dropped = pending.Dropped + 1 }

    /// Describe a configuration problem in the same shape as a startup
    /// diagnostic, so a failed validation is reportable rather than fatal.
    let describe problem =
        match problem with
        | MissingApplicationName -> FaultCode "AEGIS.CONFIG.MISSING_APPLICATION", "configuration has no application name"
        | NoSinksConfigured -> FaultCode "AEGIS.CONFIG.NO_SINKS", "configuration declares no sinks"
        | DuplicateSinkName name -> FaultCode "AEGIS.CONFIG.DUPLICATE_SINK", $"more than one sink is named {name}"
        | RequiredSinkWithoutDurableWrite name ->
            FaultCode "AEGIS.CONFIG.REQUIRED_SINK_NOT_DURABLE", $"sink {name} is required but does not support durable writes"
        | RedactionRuleWithoutName -> FaultCode "AEGIS.CONFIG.UNNAMED_REDACTION_RULE", "a redaction rule has no name"
        | InvalidQueueCapacity capacity -> FaultCode "AEGIS.CONFIG.INVALID_QUEUE_CAPACITY", $"queue capacity {capacity} is not positive"

    /// Fold configuration problems into bootstrap diagnostics.
    /// Requirement: additional 47.
    let recordProblems at problems pending =
        problems
        |> List.fold
            (fun acc problem ->
                let code, message = describe problem
                record at code message acc)
            pending

    /// Promote bootstrap diagnostics into the running system once sinks exist.
    /// Requirement: additional 20.
    let promote (config: AegisConfig) (scopeOperation: string) (pending: Pending) =
        let reports =
            pending.Entries
            |> List.map (fun (at, code, message) ->
                let fault =
                    { Id = FaultId(Id.generate at (config.Random()))
                      CorrelationId = CorrelationId(Id.generate at (config.Random()))
                      Timestamp = at
                      Application = config.Application
                      ApplicationVersion = config.Version
                      Operation = scopeOperation
                      Category = ConfigurationFailure
                      Code = code
                      Severity = Warning
                      Impact = FeatureUnavailable
                      Domain = ApplicationDomain
                      Radius = EntireApplication
                      Retention = AuditRequired
                      Persistence = RequiresIntervention
                      Owner = Some "Aegis"
                      Dependencies = [ config.Application; "Aegis" ]
                      UserMessage = "A problem was detected while starting up."
                      TechnicalDetails = Some message
                      Context = Map [ "phase", Public "bootstrap" ]
                      Recovery = ManualIntervention
                      Diagnostics = noDiagnostics
                      Cause = None }

                Aegis.report config (FaultRecorded fault))

        reports, minimal pending.Capacity

    /// What a controlled shutdown managed to do. Requirement: additional 21.
    type ShutdownOutcome =
        { Flushed: EventId list
          Unflushed: int
          Failure: (EventId * string) option
          /// Diagnostics that were still pending and could not be promoted.
          Abandoned: int }

    /// Flush deferred events once, with no retry loop: shutdown must not
    /// recurse or run indefinitely. A sink that fails here leaves its events
    /// queued and reports the fact rather than blocking exit.
    /// Requirement: additional 21.
    let shutdown (write: string -> unit) (queue: Offline.Queue) (pending: Pending) =
        let result = Offline.drain write queue

        { Flushed = result.Delivered
          Unflushed = Offline.count result.Queue
          Failure = result.Failed
          Abandoned = List.length pending.Entries }
