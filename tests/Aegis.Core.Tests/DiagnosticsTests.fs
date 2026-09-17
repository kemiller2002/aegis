module Aegis.Tests.Diagnostics

open System
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 12, 0, 0, TimeSpan.Zero)

let private fault =
    { Id = FaultId "01HXYZABCDE"
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = Some "1.4.2"
      Operation = "Chrona.TimeEntry.Load"
      Category = IntegrationFailure
      Code = FaultCode "AEGIS.NETWORK.UNAVAILABLE"
      Severity = Warning
      Impact = OperationOnly
      Persistence = Transient
      Owner = Some "GitHubIntegration"
      Dependencies = [ "Chrona"; "GitHubIntegration" ]
      UserMessage = "GitHub could not be reached."
      TechnicalDetails = Some "HttpRequestException: connection reset"
      Context = Map [ "repository", Public "aegis"; "github_token", Public "ghp_leaked" ]
      Recovery = Retry(3, Immediate)
      Cause = None }

// ----------------------------------------------------------------- breadcrumbs

[<Fact>]
let ``breadcrumbs record the sequence leading to a fault`` () =
    // Requirement: additional 2.
    let t =
        Diagnostics.trail 10
        |> Diagnostics.leave (Diagnostics.crumb at "repository" "Repository loaded" Map.empty)
        |> Diagnostics.leave (Diagnostics.crumb at "parse" "Parsed 42 entries" (Map [ "count", Public "42" ]))
        |> Diagnostics.leave (Diagnostics.crumb at "github" "Calling GitHub" Map.empty)

    Assert.Equal(3, List.length t.Entries)
    Assert.Equal("Repository loaded", t.Entries.Head.Message)
    Assert.Equal(Public "42", t.Entries.[1].Data.["count"])

[<Fact>]
let ``breadcrumb history is bounded and counts what it drops`` () =
    // Requirement: additional 2 -- must not grow without limit.
    let t =
        [ 1..20 ]
        |> List.fold (fun acc n -> Diagnostics.leave (Diagnostics.crumb at "step" $"step {n}" Map.empty) acc) (Diagnostics.trail 5)

    Assert.Equal(5, List.length t.Entries)
    Assert.Equal(15, t.Dropped)
    Assert.Equal("step 16", t.Entries.Head.Message)

[<Fact>]
let ``the most recent crumbs can be attached to a fault`` () =
    let t =
        [ 1..10 ]
        |> List.fold (fun acc n -> Diagnostics.leave (Diagnostics.crumb at "step" $"step {n}" Map.empty) acc) (Diagnostics.trail 20)

    let recent = Diagnostics.recent 3 t
    Assert.Equal(3, List.length recent)
    Assert.Equal("step 8", recent.Head.Message)

[<Fact>]
let ``asking for more crumbs than exist returns what there is`` () =
    let t = Diagnostics.trail 10 |> Diagnostics.leave (Diagnostics.crumb at "a" "only one" Map.empty)
    Assert.Single(Diagnostics.recent 5 t) |> ignore

// ------------------------------------------------------- environment metadata

[<Fact>]
let ``environment metadata is optional`` () =
    // Requirement: additional 10.
    Assert.True Diagnostics.unknownEnvironment.CommitSha.IsNone
    Assert.Empty Diagnostics.unknownEnvironment.ComponentVersions

[<Fact>]
let ``deployment identity answers which build produced a fault`` () =
    // Requirement: additional 11.
    let env =
        { Diagnostics.unknownEnvironment with
            CommitSha = Some "abc1234"
            BuildVersion = Some "2026.9.17.1"
            Branch = Some "main"
            DeploymentEnvironment = Some "production" }

    let identity = Diagnostics.deploymentIdentity env
    Assert.Equal("abc1234", identity.["commit"])
    Assert.Equal("2026.9.17.1", identity.["build"])
    Assert.Equal("production", identity.["environment"])

[<Fact>]
let ``deployment identity omits what is unknown rather than inventing it`` () =
    let identity = Diagnostics.deploymentIdentity Diagnostics.unknownEnvironment
    Assert.Empty identity

// ---------------------------------------------------------- snapshot references

[<Fact>]
let ``a snapshot is referenced rather than embedded`` () =
    // Requirement: additional 12 -- references over payloads.
    let reference =
        { Diagnostics.Location = "aegis/snapshots/2026/09/17/01ABC.json"
          Diagnostics.Digest = "sha256:deadbeef"
          Diagnostics.Summary = "42 time entries, 3 unsynced"
          Diagnostics.CapturedAt = at }

    // The reference carries identity and a summary, never the state itself.
    Assert.DoesNotContain("entries\":[", reference.Summary)
    Assert.StartsWith("sha256:", reference.Digest)

// --------------------------------------------------------- diagnostic bundles

let private bundle =
    { Diagnostics.GeneratedAt = at
      Diagnostics.Application = "Chrona"
      Diagnostics.Environment = { Diagnostics.unknownEnvironment with CommitSha = Some "abc1234" }
      Diagnostics.Faults = [ fault ]
      Diagnostics.Breadcrumbs =
        [ Diagnostics.crumb at "auth" "Refreshing credentials" (Map [ "authorization", Public "Bearer ghp_alsoleaked" ]) ]
      Diagnostics.Snapshots = []
      Diagnostics.Configuration = Map [ "github_token", "ghp_configleak"; "branch", "main" ]
      Diagnostics.SinkHealth = Map [ "github", "degraded" ]
      Diagnostics.RecoveryAttempts = [] }

[<Fact>]
let ``export redacts faults, breadcrumbs and configuration alike`` () =
    // Requirement: additional 40 -- a bundle must not bypass sink redaction.
    let exported = Diagnostics.export Redaction.defaultRules bundle
    let text = string (box exported)
    Assert.DoesNotContain("ghp_leaked", text)
    Assert.DoesNotContain("ghp_alsoleaked", text)
    Assert.DoesNotContain("ghp_configleak", text)

[<Fact>]
let ``an exported bundle leaks nothing a rule would remove`` () =
    // Requirement: additional 40.
    let exported = Diagnostics.export Redaction.defaultRules bundle
    Assert.Empty(Diagnostics.leaks Redaction.defaultRules exported)

[<Fact>]
let ``the unexported bundle does still carry secrets, which is why export exists`` () =
    // Guards the test above against passing vacuously.
    Assert.NotEmpty(Diagnostics.leaks Redaction.defaultRules bundle)

[<Fact>]
let ``export drops technical details rather than shipping them`` () =
    // Requirement: core 11 -- developers see them, exports do not carry them.
    let exported = Diagnostics.export Redaction.defaultRules bundle
    Assert.True exported.Faults.Head.TechnicalDetails.IsNone

[<Fact>]
let ``export keeps the non-sensitive material`` () =
    let exported = Diagnostics.export Redaction.defaultRules bundle
    Assert.Equal(Public "aegis", exported.Faults.Head.Context.["repository"])
    Assert.Equal("main", exported.Configuration.["branch"])
    Assert.Equal(Some "abc1234", exported.Environment.CommitSha)
    Assert.Equal("degraded", exported.SinkHealth.["github"])

// ------------------------------------------------------------- known-fault catalog

[<Fact>]
let ``the catalog describes a known fault for humans and agents`` () =
    // Requirement: additional 14.
    match Catalog.lookup (FaultCode "AEGIS.GITHUB.AUTHENTICATION_FAILED") Catalog.builtIn with
    | Some entry ->
        Assert.Equal(SecurityFailure, entry.Category)
        Assert.False entry.RetryEligible
        Assert.True entry.NotifyUser
        Assert.NotEmpty entry.Guidance.LikelyCauses
        Assert.NotEmpty entry.Guidance.SafeChecks
        Assert.True entry.EscalationGuidance.IsSome
    | None -> failwith "expected a catalog entry"

[<Fact>]
let ``an unknown code is simply absent rather than fabricated`` () =
    Assert.True (Catalog.lookup (FaultCode "SOMETHING.MADE.UP") Catalog.builtIn).IsNone

[<Fact>]
let ``the catalog can forbid an action for a fault`` () =
    // Requirement: additional 42.
    Assert.False(Catalog.permits Catalog.builtIn (FaultCode "AEGIS.DATA.HASH_MISMATCH") Recovery.CanRetry)
    Assert.False(Catalog.permits Catalog.builtIn (FaultCode "AEGIS.DATA.HASH_MISMATCH") Recovery.CanReload)

[<Fact>]
let ``integrity faults allow no automatic recovery at all`` () =
    // Requirement: core 20 -- nothing automatic may write before correctness.
    match Catalog.lookup (FaultCode "AEGIS.DATA.HASH_MISMATCH") Catalog.builtIn with
    | Some entry ->
        Assert.False entry.AutomaticRecoveryAllowed
        Assert.Equal(Critical, entry.DefaultSeverity)
    | None -> failwith "expected a catalog entry"

[<Fact>]
let ``catalog guidance cannot grant what the authority denies`` () =
    // Requirement: additional 42 -- guidance is advice, not permission.
    let permitted = Catalog.permits Catalog.builtIn (FaultCode "AEGIS.NETWORK.UNAVAILABLE") Recovery.CanRetry
    Assert.True permitted

    // Even so, a denying authority still refuses the attempt.
    let result =
        Recovery.attempt
            Recovery.denyAll
            Agent
            at
            1
            true
            (fun _ -> Ok())
            (fun () -> Some true)
            fault

    match result with
    | Recovery.Refused (Recovery.NotAuthorized _, _) -> ()
    | other -> failwith $"expected a refusal, got {other}"

[<Fact>]
let ``the catalog applies consistent classification`` () =
    // Requirement: additional 14 -- humans and agents see the same thing.
    let vague = { fault with Category = UnknownFailure; Severity = Diagnostic }
    let classified = Catalog.classify Catalog.builtIn vague
    Assert.Equal(InfrastructureFailure, classified.Category)
    Assert.Equal(Warning, classified.Severity)

[<Fact>]
let ``classification leaves unknown codes untouched`` () =
    let unknown = { fault with Code = FaultCode "NOT.IN.CATALOG"; Severity = Diagnostic }
    Assert.Equal(Diagnostic, (Catalog.classify Catalog.builtIn unknown).Severity)

// --------------------------------------------------------------- circuit breaker

let private policy =
    { Containment.ConsecutiveFailures = 3
      Containment.OpenFor = TimeSpan.FromMinutes 1. }

[<Fact>]
let ``the circuit stays closed below the failure threshold`` () =
    // Requirement: additional 6.
    Assert.Equal(Containment.Closed, Containment.circuit policy at 2 (Some at))

[<Fact>]
let ``the circuit opens after consecutive failures and blocks calls`` () =
    match Containment.circuit policy at 3 (Some at) with
    | Containment.Open until ->
        Assert.Equal(at.AddMinutes 1., until)
        Assert.False(Containment.permits (Containment.Open until))
    | other -> failwith $"expected Open, got {other}"

[<Fact>]
let ``the circuit becomes half-open once the window passes`` () =
    let state = Containment.circuit policy (at.AddMinutes 2.) 3 (Some at)
    Assert.Equal(Containment.HalfOpen, state)
    Assert.True(Containment.permits state)

[<Fact>]
let ``circuit state is derived from history so it is reproducible`` () =
    // Requirement: additional 6 -- explicit and observable, not hidden counters.
    let first = Containment.circuit policy at 5 (Some at)
    let second = Containment.circuit policy at 5 (Some at)
    Assert.Equal(first, second)

// -------------------------------------------------------------------- quarantine

let private quarantined =
    { Containment.SourceId = "entry-123"
      Containment.PayloadReference = "aegis/quarantine/entry-123.json"
      Containment.FaultId = fault.Id
      Containment.Code = FaultCode "AEGIS.DATA.INVALID_PERSISTED_STATE"
      Containment.Reason = "unparseable entry"
      Containment.At = at
      Containment.RetryEligible = false
      Containment.Released = None }

[<Fact>]
let ``quarantined data is not processed again`` () =
    // Requirement: additional 7.
    let store = Containment.quarantine quarantined Containment.noQuarantine
    Assert.True(Containment.isQuarantined "entry-123" store)
    Assert.False(Containment.isQuarantined "entry-999" store)

[<Fact>]
let ``quarantine holds a payload reference rather than the payload`` () =
    // Requirement: additional 7 -- follows the sensitive-data rules.
    Assert.StartsWith("aegis/quarantine/", quarantined.PayloadReference)

[<Fact>]
let ``releasing quarantine is explicit and dated`` () =
    let store =
        Containment.quarantine quarantined Containment.noQuarantine
        |> Containment.release (at.AddHours 3.) "entry-123"

    Assert.False(Containment.isQuarantined "entry-123" store)
    Assert.Empty(Containment.held store)

[<Fact>]
let ``held items are those not yet released`` () =
    let store =
        Containment.noQuarantine
        |> Containment.quarantine quarantined
        |> Containment.quarantine { quarantined with SourceId = "entry-456" }
        |> Containment.release at "entry-456"

    Assert.Single(Containment.held store) |> ignore

// ------------------------------------------------------------------ dead letter

let private failedAttempt n =
    { Action = Retry(3, Immediate)
      AttemptNumber = n
      Actor = Application
      Timestamp = at
      CorrelationId = CorrelationId "CORR1"
      Outcome = FailedWith "still failing" }

[<Fact>]
let ``an item is dead-lettered once its recovery budget is spent`` () =
    // Requirement: additional 8 -- deterministic and policy-driven.
    Assert.False(Containment.shouldDeadLetter 3 [ failedAttempt 1; failedAttempt 2 ])
    Assert.True(Containment.shouldDeadLetter 3 [ failedAttempt 1; failedAttempt 2; failedAttempt 3 ])

[<Fact>]
let ``successful attempts do not count toward dead-lettering`` () =
    let succeeded = { failedAttempt 2 with Outcome = Succeeded }
    Assert.False(Containment.shouldDeadLetter 2 [ failedAttempt 1; succeeded ])

[<Fact>]
let ``a dead letter carries enough to decide what to do next`` () =
    // Requirement: additional 8.
    let attempts = [ failedAttempt 1; failedAttempt 2; failedAttempt 3 ]
    let letter = Containment.deadLetter at "entry-123" "aegis/deadletter/entry-123.json" fault attempts "retries exhausted"

    Assert.Equal("entry-123", letter.ItemId)
    Assert.Equal(fault.Id, letter.FaultId)
    Assert.Equal(3, List.length letter.Attempts)
    Assert.Equal("retries exhausted", letter.FinalReason)
    // A transient fault remains reprocessable later.
    Assert.True letter.Reprocessable
    Assert.False letter.RequiresManualIntervention

[<Fact>]
let ``a dead letter needing a human says so`` () =
    let corrupt = { fault with Recovery = ManualIntervention; Persistence = RequiresIntervention }
    let letter = Containment.deadLetter at "entry-9" "ref" corrupt [] "cannot be recovered automatically"
    Assert.True letter.RequiresManualIntervention
    Assert.False letter.Reprocessable
