module Aegis.Tests.Lifecycle

open System
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 12, 0, 0, TimeSpan.Zero)

let private faultWith id code operation =
    { Id = FaultId id
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = Some "1.4.2"
      Operation = operation
      Category = IntegrationFailure
      Code = FaultCode code
      Severity = Warning
      Impact = OperationOnly
      Persistence = Transient
      Owner = Some "GitHubIntegration"
      Dependencies = [ "Chrona"; "GitHubIntegration"; "GitHubApi" ]
      UserMessage = "Unable to load time entries."
      TechnicalDetails = None
      Context = Map [ "repository", Public "aegis" ]
      Recovery = Retry(3, Immediate)
      Cause = Some(CausedByException { ExceptionType = "System.TimeoutException"; Message = "timeout"; StackTrace = None; Inner = None }) }

let private fault = faultWith "F1" "CHRONA.GITHUB.LOAD_FAILED" "Chrona.TimeEntry.Load"

// --------------------------------------------------------------- fingerprints

[<Fact>]
let ``fingerprint is stable across occurrences`` () =
    // Requirement: additional 4.
    let later =
        { fault with
            Id = FaultId "F2"
            Timestamp = at.AddHours 5.
            CorrelationId = CorrelationId "CORR2" }

    Assert.Equal(Lifecycle.fingerprint fault, Lifecycle.fingerprint later)

[<Fact>]
let ``fingerprint excludes context values`` () =
    let other = { fault with Context = Map [ "repository", Public "something-else" ] }
    Assert.Equal(Lifecycle.fingerprint fault, Lifecycle.fingerprint other)

[<Fact>]
let ``fingerprint distinguishes different problems`` () =
    let other = { fault with Code = FaultCode "CHRONA.GITHUB.SAVE_FAILED" }
    Assert.NotEqual(Lifecycle.fingerprint fault, Lifecycle.fingerprint other)

[<Fact>]
let ``fingerprint distinguishes different operations`` () =
    let other = { fault with Operation = "Chrona.TimeEntry.Save" }
    Assert.NotEqual(Lifecycle.fingerprint fault, Lifecycle.fingerprint other)

// ----------------------------------------------------------------- projection

let private projectOne events = (Lifecycle.project events).["F1"]

[<Fact>]
let ``a recorded fault projects as active`` () =
    let p = projectOne [ FaultRecorded fault ]
    Assert.Equal(Lifecycle.Active, p.State)
    Assert.Equal(1, p.Occurrences)

[<Fact>]
let ``acknowledgement does not resolve`` () =
    // Requirement: additional 17 -- the distinction the requirements insist on.
    let p = projectOne [ FaultRecorded fault; FaultAcknowledged(fault.Id, Operator, at) ]
    Assert.Equal(Lifecycle.AcknowledgedActive, p.State)
    Assert.True p.Acknowledged.IsSome
    Assert.True p.Resolution.IsNone
    Assert.Contains(p, Lifecycle.active (Lifecycle.project [ FaultRecorded fault; FaultAcknowledged(fault.Id, Operator, at) ]))

[<Fact>]
let ``resolution removes the fault from the active set but keeps its history`` () =
    // Requirement: additional 32.
    let events =
        [ FaultRecorded fault
          FaultAcknowledged(fault.Id, User, at)
          FaultResolved(fault.Id, { Timestamp = at.AddMinutes 5.; Kind = ResolvedAutomatically; Action = Some Reload; Verified = true }) ]

    let projection = Lifecycle.project events
    Assert.Empty(Lifecycle.active projection)
    let p = projection.["F1"]
    Assert.Equal(Lifecycle.Resolved, p.State)
    Assert.True p.Resolution.IsSome
    // History is not erased: the acknowledgement survives resolution.
    Assert.True p.Acknowledged.IsSome

[<Fact>]
let ``reopening is explicit and counted`` () =
    // Requirement: additional 33.
    let events =
        [ FaultRecorded fault
          FaultResolved(fault.Id, { Timestamp = at; Kind = ResolvedAutomatically; Action = None; Verified = true })
          FaultReopened(fault.Id, at.AddHours 1., "same condition returned") ]

    let p = projectOne events
    Assert.Equal(Lifecycle.Active, p.State)
    Assert.Equal(1, p.Reopenings)
    Assert.True p.Resolution.IsNone

[<Fact>]
let ``supersession preserves the original and points at the replacement`` () =
    // Requirement: additional 34.
    let better = faultWith "F2" "AEGIS.AUTH.PROVIDER_UNAVAILABLE" "Chrona.TimeEntry.Load"

    let projection =
        Lifecycle.project
            [ FaultRecorded fault
              FaultRecorded better
              FaultSuperseded(fault.Id, better.Id, at.AddMinutes 1.) ]

    Assert.Equal(Lifecycle.Superseded, projection.["F1"].State)
    Assert.Equal(Some better.Id, projection.["F1"].SupersededBy)
    Assert.Equal(Lifecycle.Active, projection.["F2"].State)
    Assert.Single(Lifecycle.active projection) |> ignore

[<Fact>]
let ``repeated occurrences aggregate without losing the record`` () =
    // Requirements: additional 3, 35.
    let events =
        [ FaultRecorded fault
          FaultRepeated(fault.Id, at.AddMinutes 1.)
          FaultRepeated(fault.Id, at.AddMinutes 2.) ]

    let p = projectOne events
    Assert.Equal(3, p.Occurrences)
    Assert.Equal(at, p.FirstSeen)
    Assert.Equal(at.AddMinutes 2., p.LastSeen)

[<Fact>]
let ``escalation advances severity and keeps the history`` () =
    // Requirement: additional 36 -- severity is not silently overwritten.
    let events =
        [ FaultRecorded fault
          FaultEscalated(fault.Id, Warning, FaultSeverity.Error, at.AddMinutes 5.)
          FaultEscalated(fault.Id, FaultSeverity.Error, Critical, at.AddMinutes 9.) ]

    let p = projectOne events
    Assert.Equal(Critical, p.Severity)
    Assert.Equal(2, List.length p.EscalationHistory)
    Assert.Equal(Warning, p.Fault.Severity) // the original record is unchanged

[<Fact>]
let ``recovery attempts are recorded and concluded`` () =
    // Requirements: additional 15, 37, 38.
    let attempt =
        { Action = Reauthenticate
          AttemptNumber = 1
          Actor = Agent
          Timestamp = at
          CorrelationId = CorrelationId "CORR1"
          Outcome = AwaitingVerification }

    let p =
        projectOne
            [ FaultRecorded fault
              RecoveryStarted(fault.Id, attempt)
              RecoveryConcluded(fault.Id, 1, Succeeded, at.AddSeconds 3.) ]

    Assert.Single p.Attempts |> ignore
    Assert.Equal(Succeeded, p.Attempts.Head.Outcome)
    Assert.Equal(Agent, p.Attempts.Head.Actor)

[<Fact>]
let ``recovery returning without success is not treated as recovered`` () =
    // Requirement: additional 15.
    let attempt =
        { Action = Reauthenticate
          AttemptNumber = 1
          Actor = Application
          Timestamp = at
          CorrelationId = CorrelationId "CORR1"
          Outcome = AwaitingVerification }

    let p = projectOne [ FaultRecorded fault; RecoveryStarted(fault.Id, attempt) ]
    Assert.Equal(AwaitingVerification, p.Attempts.Head.Outcome)
    Assert.Equal(Lifecycle.Active, p.State)

[<Fact>]
let ``projection is a pure fold: order-independent for independent faults`` () =
    // Requirement: additional 31.
    let other = faultWith "F2" "CHRONA.GITHUB.SAVE_FAILED" "Chrona.TimeEntry.Save"
    let a = Lifecycle.project [ FaultRecorded fault; FaultRecorded other ]
    let b = Lifecycle.project [ FaultRecorded other; FaultRecorded fault ]
    Assert.Equal<Set<string>>(a |> Map.keys |> Set.ofSeq, b |> Map.keys |> Set.ofSeq)

[<Fact>]
let ``recurrence is detected by fingerprint`` () =
    // Requirement: additional 33 -- recurrence vs unrelated new occurrence.
    let projection = Lifecycle.project [ FaultRecorded fault ]
    let sameProblem = { fault with Id = FaultId "F9"; Timestamp = at.AddDays 1. }
    let different = faultWith "F8" "CHRONA.GITHUB.SAVE_FAILED" "Chrona.TimeEntry.Save"
    Assert.True (Lifecycle.recurrenceOf projection sameProblem).IsSome
    Assert.True (Lifecycle.recurrenceOf projection different).IsNone

[<Fact>]
let ``faults group by fingerprint for shared-cause analysis`` () =
    // Requirements: additional 3, 46.
    let twin = { fault with Id = FaultId "F2" }
    let projection = Lifecycle.project [ FaultRecorded fault; FaultRecorded twin ]
    let groups = Lifecycle.byFingerprint projection
    Assert.Single groups |> ignore
    Assert.Equal(2, groups.[Lifecycle.fingerprint fault] |> List.length)

[<Fact>]
let ``suppressed faults still count as occurrences`` () =
    // Requirement: additional 26 -- presentation throttled, fidelity preserved.
    let p = projectOne [ FaultRecorded fault; FaultSuppressed(fault, "rate limited") ]
    Assert.Equal(2, p.Occurrences)

[<Fact>]
let ``events for unknown faults are ignored rather than inventing records`` () =
    let projection = Lifecycle.project [ FaultAcknowledged(FaultId "NOPE", User, at) ]
    Assert.Empty projection

// -------------------------------------------------------------- offline queue

[<Fact>]
let ``queued entries preserve order and identity`` () =
    // Requirement: logging 20.
    let queue =
        Offline.create 10
        |> Offline.enqueue (EventId "E1") "{\"n\":1}"
        |> Offline.enqueue (EventId "E2") "{\"n\":2}"
        |> Offline.enqueue (EventId "E3") "{\"n\":3}"

    Assert.Equal<EventId list>([ EventId "E1"; EventId "E2"; EventId "E3" ], Offline.pendingIds queue)

[<Fact>]
let ``draining delivers everything in order and empties the queue`` () =
    let delivered = ResizeArray<string>()

    let result =
        Offline.create 10
        |> Offline.enqueue (EventId "E1") "one"
        |> Offline.enqueue (EventId "E2") "two"
        |> Offline.drain delivered.Add

    Assert.Equal<string list>([ "one"; "two" ], List.ofSeq delivered)
    Assert.Equal(0, Offline.count result.Queue)
    Assert.True result.Failed.IsNone

[<Fact>]
let ``a failure mid-drain keeps the rest queued in order`` () =
    // Requirement: logging 33 -- a partial outage must not reorder history.
    let seen = ResizeArray<string>()

    let write payload =
        seen.Add payload
        if payload = "two" then failwith "sink down"

    let result =
        Offline.create 10
        |> Offline.enqueue (EventId "E1") "one"
        |> Offline.enqueue (EventId "E2") "two"
        |> Offline.enqueue (EventId "E3") "three"
        |> Offline.drain write

    Assert.Equal<string list>([ "one"; "two" ], List.ofSeq seen) // stopped, did not skip ahead
    Assert.Equal<EventId list>([ EventId "E2"; EventId "E3" ], Offline.pendingIds result.Queue)
    Assert.Equal(Some(EventId "E2", "sink down"), result.Failed)
    Assert.Equal<EventId list>([ EventId "E1" ], result.Delivered)

[<Fact>]
let ``a full queue drops the oldest and counts the loss`` () =
    // Bounded memory is required; silent loss is not acceptable.
    let queue =
        [ 1..5 ]
        |> List.fold (fun q n -> Offline.enqueue (EventId $"E{n}") $"payload{n}" q) (Offline.create 3)

    Assert.Equal(3, Offline.count queue)
    Assert.Equal(2, queue.Dropped)
    Assert.Equal<EventId list>([ EventId "E3"; EventId "E4"; EventId "E5" ], Offline.pendingIds queue)

[<Fact>]
let ``queued payloads are already redacted`` () =
    // Requirement: logging 20, 21 -- redaction state is preserved, not re-derived.
    let rules = Redaction.defaultRules
    let secretFault = { fault with Context = Map [ "github_token", Public "ghp_leaked" ] }
    let payload = Serialization.event rules (EventId "E1") (FaultRecorded secretFault)
    let queue = Offline.create 5 |> Offline.enqueue (EventId "E1") payload
    Assert.DoesNotContain("ghp_leaked", queue.Entries.Head.Payload)

// ------------------------------------------------- lifecycle event serialization

[<Fact>]
let ``lifecycle events serialize with the schema and their fault id`` () =
    // Requirements: logging 12, 23.
    let events =
        [ FaultAcknowledged(fault.Id, Operator, at)
          FaultResolved(fault.Id, { Timestamp = at; Kind = ResolvedManually; Action = Some Reauthenticate; Verified = true })
          FaultReopened(fault.Id, at, "recurred")
          FaultEscalated(fault.Id, Warning, Critical, at)
          FaultSuperseded(fault.Id, FaultId "F2", at)
          FaultRepeated(fault.Id, at) ]

    for ev in events do
        let payload = Serialization.event Redaction.defaultRules (EventId "E1") ev
        Assert.Contains($"\"schema\":\"{Schema.Event}\"", payload)
        Assert.Contains("\"faultId\":\"F1\"", payload)
        Assert.Contains($"\"eventType\":\"{Serialization.eventTypeName ev}\"", payload)

[<Fact>]
let ``resolution serialization records whether it was verified`` () =
    // Requirements: additional 15, 32.
    let payload =
        Serialization.event
            Redaction.defaultRules
            (EventId "E1")
            (FaultResolved(fault.Id, { Timestamp = at; Kind = ResolvedAutomatically; Action = Some Reload; Verified = false }))

    Assert.Contains("\"verified\":false", payload)
    Assert.Contains("\"resolutionKind\":\"Automatic\"", payload)
