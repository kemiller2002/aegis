module Aegis.Tests.Presentation

open System
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 11, 0, 0, TimeSpan.Zero)

let private faultOf id severity impact recovery dependencies =
    { Id = FaultId id
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = None
      Operation = "Chrona.TimeEntry.Load"
      Category = IntegrationFailure
      Code = FaultCode "CHRONA.GITHUB.LOAD_FAILED"
      Severity = severity
      Impact = impact
      Domain = IntegrationDomain
      Radius = OneOperation
      Retention = DiagnosticOnly
      Persistence = Transient
      Owner = Some "GitHubIntegration"
      Dependencies = dependencies
      UserMessage = "GitHub could not be reached."
      TechnicalDetails = Some "HttpRequestException at Foo.Bar line 42, token ghp_secret"
      Context = Map.empty
      Recovery = recovery
      Diagnostics = noDiagnostics
      Cause = None }

let private plain = faultOf "F1" FaultSeverity.Warning OperationOnly (Retry(3, Immediate)) [ "Chrona"; "GitHubIntegration" ]

// -------------------------------------------------------------- presentation

[<Fact>]
let ``presentation carries only the user-facing message`` () =
    // Requirement: core 11 -- no stack trace, token or internal path.
    let presented = Presentation.present "Unable to load time entries" plain
    Assert.Equal("GitHub could not be reached.", presented.Message)
    Assert.DoesNotContain("ghp_secret", presented.Message)
    Assert.DoesNotContain("HttpRequestException", presented.Message)
    Assert.DoesNotContain("Foo.Bar", presented.Message)

[<Fact>]
let ``presentation offers the recovery actions the policy allows`` () =
    // Requirement: core 10.
    let presented = Presentation.present "Unable to load time entries" plain
    Assert.Single presented.Actions |> ignore
    Assert.Equal(Recovery.CanRetry, presented.Actions.Head.Capability)
    Assert.Equal("Try again", presented.Actions.Head.Label)

[<Fact>]
let ``a fault needing manual intervention offers no actions`` () =
    let manual = faultOf "F2" FaultSeverity.Critical ApplicationUnsafe ManualIntervention [ "Chrona" ]
    Assert.Empty (Presentation.present "Data problem" manual).Actions

[<Fact>]
let ``the reference is derived from the fault id not the message`` () =
    // Requirement: core 31 -- a person can quote it back.
    let presented = Presentation.present "t" (faultOf "01HXYZABCDE" FaultSeverity.Warning OperationOnly NoRecovery [])
    Assert.StartsWith("AG-", presented.Reference)

[<Fact>]
let ``Aegis produces no markup`` () =
    // Requirement: core 10 -- Limen renders, Aegis does not.
    let presented = Presentation.present "Unable to load time entries" plain
    for text in [ presented.Title; presented.Message; presented.Reference ] do
        Assert.DoesNotContain("<", text)
        Assert.DoesNotContain(">", text)

// ------------------------------------------------------------------- intent

[<Fact>]
let ``a diagnostic fault is silent`` () =
    // Requirement: additional 25 -- not every fault is visible.
    Assert.Equal(Presentation.Silent, Presentation.intentFor (faultOf "F" FaultSeverity.Diagnostic OperationOnly NoRecovery []))

[<Fact>]
let ``an unsafe application blocks`` () =
    Assert.Equal(Presentation.Blocking, Presentation.intentFor (faultOf "F" FaultSeverity.Error ApplicationUnsafe ReadOnlyRecovery []))

[<Fact>]
let ``an operation-scoped fault is shown inline`` () =
    Assert.Equal(Presentation.Inline, Presentation.intentFor (faultOf "F" FaultSeverity.Warning OperationOnly NoRecovery []))

[<Fact>]
let ``an unavailable feature notifies`` () =
    Assert.Equal(Presentation.Notification, Presentation.intentFor (faultOf "F" FaultSeverity.Warning FeatureUnavailable NoRecovery []))

// ---------------------------------------------------------------- throttling

[<Fact>]
let ``fifty occurrences produce one notification`` () =
    // Requirement: additional 26 -- the requirements' own worked example.
    let decisions, _ =
        [ 1..50 ]
        |> List.fold
            (fun (decisions, state) n ->
                let notify, next = Presentation.shouldNotify (at.AddSeconds(float n)) plain state
                decisions @ [ notify ], next)
            ([], Presentation.throttle (TimeSpan.FromMinutes 5.))

    Assert.Equal(1, decisions |> List.filter id |> List.length)

[<Fact>]
let ``notification resumes after the window passes`` () =
    let state = Presentation.throttle (TimeSpan.FromMinutes 5.)
    let first, state = Presentation.shouldNotify at plain state
    let during, state = Presentation.shouldNotify (at.AddMinutes 1.) plain state
    let after, _ = Presentation.shouldNotify (at.AddMinutes 6.) plain state
    Assert.True first
    Assert.False during
    Assert.True after

[<Fact>]
let ``throttling is keyed by fingerprint so different problems both notify`` () =
    let other = { plain with Id = FaultId "F9"; Code = FaultCode "CHRONA.GITHUB.SAVE_FAILED" }
    let state = Presentation.throttle (TimeSpan.FromMinutes 5.)
    let first, state = Presentation.shouldNotify at plain state
    let second, _ = Presentation.shouldNotify at other state
    Assert.True first
    Assert.True second

[<Fact>]
let ``a silent fault never notifies`` () =
    let quiet = faultOf "F" FaultSeverity.Diagnostic OperationOnly NoRecovery []
    let notify, _ = Presentation.shouldNotify at quiet (Presentation.throttle (TimeSpan.FromMinutes 5.))
    Assert.False notify

// ------------------------------------------------------- persistence state

[<Fact>]
let ``persistence state reports synchronized when nothing is queued`` () =
    // Requirement: logging 45.
    Assert.Equal(Presentation.Synchronized, Presentation.persistenceState (Offline.create 10) None true)

[<Fact>]
let ``persistence state reports how many events are queued`` () =
    let queue = Offline.create 10 |> Offline.enqueue (EventId "E1") "x" |> Offline.enqueue (EventId "E2") "y"
    Assert.Equal(Presentation.Queued 2, Presentation.persistenceState queue None true)

[<Fact>]
let ``persistence state reports the last failure when the sink is down`` () =
    match Presentation.persistenceState (Offline.create 10) (Some "github unreachable") false with
    | Presentation.LastSynchronizationFailed reason -> Assert.Equal("github unreachable", reason)
    | other -> failwith $"unexpected {other}"

// ------------------------------------------------------------------ escalation

let private projectedOf fault occurrences =
    let events = FaultRecorded fault :: List.replicate (occurrences - 1) (FaultRepeated(fault.Id, at))
    (Lifecycle.project events).[fault.Id.Value]

[<Fact>]
let ``severity escalates after repeated occurrences`` () =
    // Requirement: additional 5.
    let policy = { Escalation.Rules = [ Escalation.AfterOccurrences(5, FaultSeverity.Error) ] }

    match Escalation.evaluate policy at (projectedOf plain 5) with
    | Some (FaultEscalated (_, previous, current, _)) ->
        Assert.Equal(FaultSeverity.Warning, previous)
        Assert.Equal(FaultSeverity.Error, current)
    | other -> failwith $"expected an escalation, got {other}"

[<Fact>]
let ``escalation does not fire before the threshold`` () =
    let policy = { Escalation.Rules = [ Escalation.AfterOccurrences(5, FaultSeverity.Error) ] }
    Assert.True (Escalation.evaluate policy at (projectedOf plain 4)).IsNone

[<Fact>]
let ``escalation never lowers severity`` () =
    // Requirement: additional 36 -- a policy cannot quietly downgrade.
    let critical = { plain with Severity = FaultSeverity.Critical }
    let policy = { Escalation.Rules = [ Escalation.AfterOccurrences(1, FaultSeverity.Warning) ] }
    Assert.True (Escalation.evaluate policy at (projectedOf critical 3)).IsNone

[<Fact>]
let ``a resolved fault does not escalate`` () =
    let policy = { Escalation.Rules = [ Escalation.AfterOccurrences(1, FaultSeverity.Critical) ] }

    let projection =
        Lifecycle.project
            [ FaultRecorded plain
              FaultResolved(plain.Id, { Timestamp = at; Kind = ResolvedAutomatically; Action = None; Verified = true }) ]

    Assert.True (Escalation.evaluate policy at projection.["F1"]).IsNone

[<Fact>]
let ``a fault active beyond the window escalates`` () =
    let policy = { Escalation.Rules = [ Escalation.AfterActiveFor(TimeSpan.FromMinutes 30., FaultSeverity.Critical) ] }
    Assert.True (Escalation.evaluate policy (at.AddHours 1.) (projectedOf plain 1)).IsSome
    Assert.True (Escalation.evaluate policy (at.AddMinutes 5.) (projectedOf plain 1)).IsNone

[<Fact>]
let ``a transient fault becomes persistent after the window`` () =
    // Requirement: additional 5.
    let policy = { Escalation.Rules = [ Escalation.TransientBecomesPersistentAfter(TimeSpan.FromMinutes 10.) ] }
    Assert.Equal(Some Persistent, Escalation.reclassify policy (at.AddMinutes 11.) (projectedOf plain 1))
    Assert.Equal(None, Escalation.reclassify policy (at.AddMinutes 5.) (projectedOf plain 1))

// ------------------------------------------------------- root-cause grouping

[<Fact>]
let ``faults sharing a dependency group together`` () =
    // Requirements: additional 45, 46 -- the requirements' worked example.
    let chrona = faultOf "F1" FaultSeverity.Warning OperationOnly NoRecovery [ "Chrona"; "GitHubIntegration"; "GitHubApi" ]
    let summa = { faultOf "F2" FaultSeverity.Warning OperationOnly NoRecovery [ "Summa"; "GitHubIntegration"; "GitHubApi" ] with Application = "Summa" }
    let projection = Lifecycle.project [ FaultRecorded chrona; FaultRecorded summa ]

    let groups = Escalation.byDependency projection
    Assert.Equal(2, groups.["GitHubApi"] |> List.length)
    Assert.Single groups.["Chrona"] |> ignore

[<Fact>]
let ``the likeliest root cause is the innermost shared dependency`` () =
    // Requirement: additional 46 -- several symptoms, one cause.
    let chrona = faultOf "F1" FaultSeverity.Warning OperationOnly NoRecovery [ "Chrona"; "GitHubIntegration"; "GitHubApi" ]
    let summa = { faultOf "F2" FaultSeverity.Warning OperationOnly NoRecovery [ "Summa"; "GitHubIntegration"; "GitHubApi" ] with Application = "Summa" }
    let projection = Lifecycle.project [ FaultRecorded chrona; FaultRecorded summa ]

    match Escalation.likelyRootCause projection with
    | Some (dependency, faults) ->
        Assert.Equal("GitHubApi", dependency)
        Assert.Equal(2, List.length faults)
    | None -> failwith "expected a root cause"

[<Fact>]
let ``a single fault is not reported as a shared root cause`` () =
    let projection = Lifecycle.project [ FaultRecorded plain ]
    Assert.True (Escalation.likelyRootCause projection).IsNone

[<Fact>]
let ``resolved faults do not contribute to root-cause grouping`` () =
    let chrona = faultOf "F1" FaultSeverity.Warning OperationOnly NoRecovery [ "Chrona"; "GitHubApi" ]
    let summa = { faultOf "F2" FaultSeverity.Warning OperationOnly NoRecovery [ "Summa"; "GitHubApi" ] with Application = "Summa" }

    let projection =
        Lifecycle.project
            [ FaultRecorded chrona
              FaultRecorded summa
              FaultResolved(summa.Id, { Timestamp = at; Kind = ResolvedAutomatically; Action = None; Verified = true }) ]

    Assert.True (Escalation.likelyRootCause projection).IsNone

[<Fact>]
let ``the dependency chain is serialized for stored events`` () =
    // Requirement: additional 45 -- grouping must work off stored history.
    let payload = Serialization.event Redaction.defaultRules (EventId "E1") (FaultRecorded plain)
    Assert.Contains("\"dependencies\":[\"Chrona\",\"GitHubIntegration\"]", payload)
