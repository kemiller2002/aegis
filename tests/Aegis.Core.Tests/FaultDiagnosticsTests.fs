module Aegis.Tests.FaultDiagnostics

open System
open Xunit
open Aegis
open Aegis.Integration.GitHub

let private at = DateTimeOffset(2026, 9, 17, 15, 0, 0, TimeSpan.Zero)

let private fault =
    { Id = FaultId "01F1"
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = Some "1.4.2"
      Operation = "Chrona.TimeEntry.Load"
      Category = IntegrationFailure
      Code = FaultCode "CHRONA.GITHUB.LOAD_FAILED"
      Severity = Warning
      Impact = OperationOnly
      Domain = IntegrationDomain
      Radius = OneOperation
      Retention = DiagnosticOnly
      Persistence = Transient
      Owner = Some "GitHubIntegration"
      Dependencies = [ "Chrona"; "GitHubIntegration" ]
      UserMessage = "GitHub could not be reached."
      TechnicalDetails = None
      Context = Map.empty
      Recovery = NoRecovery
      Diagnostics = noDiagnostics
      Cause = None }

let private serialize f = Serialization.event Redaction.defaultRules (EventId "01E1") (FaultRecorded f)

// ------------------------------------------------- failure domain and radius

[<Fact>]
let ``a fault carries its failure domain`` () =
    // Requirement: additional 43.
    Assert.Contains("\"domain\":\"Integration\"", serialize fault)
    Assert.Contains("\"domain\":\"Repository\"", serialize { fault with Domain = RepositoryDomain })

[<Fact>]
let ``blast radius complements impact rather than replacing it`` () =
    // Requirement: additional 44 -- impact says how badly, radius how widely.
    let wide = { fault with Impact = OperationOnly; Radius = EntireApplication }
    let payload = serialize wide
    Assert.Contains("\"impact\":\"OperationOnly\"", payload)
    Assert.Contains("\"radius\":\"EntireApplication\"", payload)

[<Fact>]
let ``every failure domain and radius serializes distinctly`` () =
    let domains =
        [ LocalOperation; FeatureDomain; IntegrationDomain; RepositoryDomain
          ApplicationDomain; EnvironmentDomain; ExternalDependency ]
        |> List.map (fun d -> serialize { fault with Domain = d })

    let radii =
        [ OneItem; OneOperation; OneFeature; OneRepository; OneSession; EntireApplication ]
        |> List.map (fun r -> serialize { fault with Radius = r })

    Assert.Equal(7, domains |> List.distinct |> List.length)
    Assert.Equal(6, radii |> List.distinct |> List.length)

[<Fact>]
let ``the GitHub integration declares domain and radius per failure`` () =
    // Requirements: additional 43, 44 -- the assembly that knows what failed
    // also knows how far it reaches.
    Assert.Equal(ExternalDependency, GitHubFailure.mapping.Domain GitHubFailure.AuthenticationFailed)
    Assert.Equal(OneSession, GitHubFailure.mapping.Radius GitHubFailure.AuthenticationFailed)
    Assert.Equal(RepositoryDomain, GitHubFailure.mapping.Domain (GitHubFailure.RepositoryNotFound "r"))
    Assert.Equal(OneOperation, GitHubFailure.mapping.Radius GitHubFailure.Timeout)

// -------------------------------------------------------------- retention

[<Fact>]
let ``retention intent is represented in the event model`` () =
    // Requirement: logging 26.
    Assert.Contains("\"retention\":\"DiagnosticOnly\"", serialize fault)
    Assert.Contains("\"retention\":\"AuditRequired\"", serialize { fault with Retention = AuditRequired })
    Assert.Contains("\"retention\":\"RetainDays(90)\"", serialize { fault with Retention = RetainDays 90 })

[<Fact>]
let ``a security failure is audit material and a timeout is not`` () =
    // Requirement: logging 26 applied by the integration assembly.
    Assert.Equal(AuditRequired, GitHubFailure.mapping.Retention GitHubFailure.AuthenticationFailed)
    Assert.Equal(DiagnosticOnly, GitHubFailure.mapping.Retention GitHubFailure.Timeout)

[<Fact>]
let ``integrity faults are audit-required`` () =
    // Correctness problems must not be discarded on a diagnostic schedule.
    Assert.Equal(AuditRequired, Integrity.mapping.Retention (Integrity.HashMismatch("a", "b")))

// ---------------------------------------------------------- fault schema

[<Fact>]
let ``a fault serializes with the fault schema version`` () =
    // Requirement: core 37 -- previously declared but never used.
    let payload = Serialization.fault Redaction.defaultRules fault
    Assert.Contains($"\"schema\":\"{Schema.Fault}\"", payload)
    Assert.DoesNotContain(Schema.Event, payload)

[<Fact>]
let ``a fault payload carries the fault's own fields`` () =
    let payload = Serialization.fault Redaction.defaultRules fault
    Assert.Contains("\"faultId\":\"01F1\"", payload)
    Assert.Contains("\"code\":\"CHRONA.GITHUB.LOAD_FAILED\"", payload)
    Assert.Contains("\"domain\":\"Integration\"", payload)

[<Fact>]
let ``a fault payload is not mistaken for an event`` () =
    // An event has its own identity; a fault payload should not claim one.
    let payload = Serialization.fault Redaction.defaultRules fault
    Assert.DoesNotContain("\"eventType\"", payload)

// -------------------------------------------------------- attached breadcrumbs

let private trailOf () =
    Diagnostics.trail 10
    |> Diagnostics.leave (Diagnostics.crumb at "repository" "Repository loaded" Map.empty)
    |> Diagnostics.leave (Diagnostics.crumb (at.AddSeconds 1.) "parse" "Parsed 42 entries" (Map [ "count", Public "42" ]))
    |> Diagnostics.leave (Diagnostics.crumb (at.AddSeconds 2.) "github" "Calling GitHub" Map.empty)

[<Fact>]
let ``breadcrumbs can be attached to a fault`` () =
    // Requirement: additional 2 -- "a fault may attach the most recent
    // relevant breadcrumbs", which needs the fault to be able to carry them.
    let attached = Diagnostics.attach 2 (trailOf ()) None None fault
    Assert.Equal(2, List.length attached.Diagnostics.Breadcrumbs)
    Assert.Equal("Parsed 42 entries", attached.Diagnostics.Breadcrumbs.Head.Message)

[<Fact>]
let ``attached breadcrumbs reach the serialized event`` () =
    let attached = Diagnostics.attach 3 (trailOf ()) None None fault
    let payload = serialize attached
    Assert.Contains("\"breadcrumbs\"", payload)
    Assert.Contains("Repository loaded", payload)
    Assert.Contains("Calling GitHub", payload)

[<Fact>]
let ``breadcrumb data is redacted like any other context`` () =
    // Requirement: logging 21 -- a breadcrumb must not become a way around
    // redaction.
    let leaky =
        Diagnostics.trail 10
        |> Diagnostics.leave (Diagnostics.crumb at "auth" "Refreshing" (Map [ "github_token", Public "ghp_leaked" ]))

    let payload = serialize (Diagnostics.attach 1 leaky None None fault)
    Assert.DoesNotContain("ghp_leaked", payload)
    Assert.Contains(Redaction.Placeholder, payload)

[<Fact>]
let ``a fault with no breadcrumbs emits no breadcrumb field`` () =
    Assert.DoesNotContain("\"breadcrumbs\"", serialize fault)

// ------------------------------------------- attached environment and snapshot

let private environment =
    { unknownEnvironment with
        ApplicationVersion = Some "1.4.2"
        CommitSha = Some "abc1234"
        Branch = Some "main"
        DeploymentEnvironment = Some "production"
        ComponentVersions = Map [ "limen", "0.5.1" ] }

[<Fact>]
let ``environment metadata reaches the serialized event`` () =
    // Requirement: additional 10 -- previously a type nothing attached.
    let payload = serialize (Diagnostics.attach 0 (Diagnostics.trail 1) (Some environment) None fault)
    Assert.Contains("\"commitSha\":\"abc1234\"", payload)
    Assert.Contains("\"deploymentEnvironment\":\"production\"", payload)
    Assert.Contains("\"limen\":\"0.5.1\"", payload)

[<Fact>]
let ``deployment identity answers which build produced the fault`` () =
    // Requirement: additional 11.
    let identity = Diagnostics.deploymentIdentity environment
    Assert.Equal("abc1234", identity.["commit"])
    Assert.Equal("production", identity.["environment"])

[<Fact>]
let ``unknown environment fields are omitted rather than emitted empty`` () =
    let payload = serialize (Diagnostics.attach 0 (Diagnostics.trail 1) (Some unknownEnvironment) None fault)
    Assert.DoesNotContain("\"commitSha\"", payload)

[<Fact>]
let ``a snapshot reference reaches the event without the state itself`` () =
    // Requirement: additional 12 -- references over payloads.
    let snapshot =
        { Location = "aegis/snapshots/2026/09/17/01ABC.json"
          Digest = "sha256:deadbeef"
          Summary = "42 time entries, 3 unsynced"
          CapturedAt = at }

    let payload = serialize (Diagnostics.attach 0 (Diagnostics.trail 1) None (Some snapshot) fault)
    Assert.Contains("\"digest\":\"sha256:deadbeef\"", payload)
    Assert.Contains("\"summary\":\"42 time entries, 3 unsynced\"", payload)
    Assert.Contains("aegis/snapshots/2026/09/17/01ABC.json", payload)

[<Fact>]
let ``attached diagnostics survive indexing`` () =
    // The searchable fields must still parse once diagnostics are present.
    let attached = Diagnostics.attach 3 (trailOf ()) (Some environment) None fault

    match Store.index (serialize attached) with
    | Ok indexed -> Assert.Equal(Some(FaultId "01F1"), indexed.FaultId)
    | Result.Error e -> failwith $"{e}"
