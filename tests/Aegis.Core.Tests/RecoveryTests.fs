module Aegis.Tests.Recovery

open System
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 9, 17, 10, 0, 0, TimeSpan.Zero)

let private faultWith recovery category impact =
    { Id = FaultId "F1"
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = None
      Operation = "Chrona.TimeEntry.Load"
      Category = category
      Code = FaultCode "AEGIS.GITHUB.AUTHENTICATION_FAILED"
      Severity = Warning
      Impact = impact
      Persistence = Transient
      Owner = Some "GitHubIntegration"
      UserMessage = "GitHub sign-in is required."
      TechnicalDetails = None
      Context = Map.empty
      Recovery = recovery
      Cause = None }

let private allow = { Recovery.Authorize = fun _ _ -> Recovery.Authorized }
let private succeeds _ = Ok()
let private verified () = Some true

// -------------------------------------------------------------- authorization

[<Fact>]
let ``recovery is not attempted without authorization`` () =
    // Requirement: core 9 -- Aegis proposes, the authority decides.
    let performed = ref false

    let result =
        Recovery.attempt
            Recovery.denyAll
            Application
            at
            1
            true
            (fun _ ->
                performed.Value <- true
                Ok())
            verified
            (faultWith Reload IntegrationFailure OperationOnly)

    match result with
    | Recovery.Refused (Recovery.NotAuthorized _, _) -> ()
    | other -> failwith $"expected a refusal, got {other}"

    Assert.False performed.Value

[<Fact>]
let ``the default authority permits nothing`` () =
    // Safe default: inaction rather than unauthorized recovery.
    match Recovery.denyAll.Authorize (faultWith Reload IntegrationFailure OperationOnly) Reload with
    | Recovery.Denied _ -> ()
    | other -> failwith $"expected Denied, got {other}"

[<Fact>]
let ``an action needing approval is refused distinctly from one denied`` () =
    let authority = { Recovery.Authorize = fun _ _ -> Recovery.RequiresApproval "operator must confirm" }

    match
        Recovery.attempt authority Agent at 1 true succeeds verified (faultWith Reload IntegrationFailure OperationOnly)
    with
    | Recovery.Refused (Recovery.NeedsApproval reason, _) -> Assert.Equal("operator must confirm", reason)
    | other -> failwith $"expected NeedsApproval, got {other}"

[<Fact>]
let ``an agent cannot bypass the authority`` () =
    // Requirement: additional 28 -- agents act through declared capabilities
    // and approved transitions only.
    let performed = ref false

    Recovery.attempt
        { Recovery.Authorize = fun _ _ -> Recovery.Denied "not legal in this state" }
        Agent
        at
        1
        true
        (fun _ ->
            performed.Value <- true
            Ok())
        verified
        (faultWith RecoveryPolicy.Reauthenticate SecurityFailure FeatureUnavailable)
    |> ignore

    Assert.False performed.Value

// ------------------------------------------------------------------ verification

[<Fact>]
let ``recovery that runs but leaves the condition succeeds only if verified`` () =
    // Requirement: additional 15 -- returning without throwing is not success.
    let result =
        Recovery.attempt allow Application at 1 true succeeds (fun () -> Some false) (faultWith Reload IntegrationFailure OperationOnly)

    match result with
    | Recovery.Attempt attempted ->
        match attempted.Outcome with
        | FailedWith reason -> Assert.Contains("condition persists", reason)
        | other -> failwith $"expected a failure, got {other}"
    | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``verified recovery succeeds`` () =
    match Recovery.attempt allow Application at 1 true succeeds verified (faultWith Reload IntegrationFailure OperationOnly) with
    | Recovery.Attempt attempted -> Assert.Equal(Succeeded, attempted.Outcome)
    | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``recovery stays awaiting verification when verification is impossible`` () =
    // Requirement: additional 15 -- only claim what can be established.
    match Recovery.attempt allow Application at 1 true succeeds (fun () -> None) (faultWith Reload IntegrationFailure OperationOnly) with
    | Recovery.Attempt attempted -> Assert.Equal(AwaitingVerification, attempted.Outcome)
    | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``a recovery action that fails is recorded as failed`` () =
    match
        Recovery.attempt allow Application at 1 true (fun _ -> Result.Error "token endpoint down") verified (faultWith Reload IntegrationFailure OperationOnly)
    with
    | Recovery.Attempt attempted -> Assert.Equal(FailedWith "token endpoint down", attempted.Outcome)
    | other -> failwith $"expected an attempt, got {other}"

// ------------------------------------------------------------------------ retry

[<Fact>]
let ``retry stops once the policy's attempts are exhausted`` () =
    // Requirement: core 21.
    let fault = faultWith (Retry(3, Immediate)) InfrastructureFailure OperationOnly

    match Recovery.attempt allow Application at 4 true succeeds verified fault with
    | Recovery.Refused (Recovery.AttemptsExhausted attempts, _) -> Assert.Equal(3, attempts)
    | other -> failwith $"expected exhaustion, got {other}"

[<Fact>]
let ``a non-idempotent operation is not repeated`` () =
    // Requirement: core 21 -- a failed GET and a partial payment differ.
    let fault = faultWith (Retry(3, Immediate)) IntegrationFailure OperationOnly
    let performed = ref 0

    let result =
        Recovery.attempt allow Application at 2 false (fun _ ->
            System.Threading.Interlocked.Increment performed |> ignore
            Ok()) verified fault

    match result with
    | Recovery.Refused (Recovery.UnsafeToRepeat, _) -> ()
    | other -> failwith $"expected UnsafeToRepeat, got {other}"

    Assert.Equal(0, performed.Value)

[<Fact>]
let ``a non-idempotent operation may still be attempted once`` () =
    let fault = faultWith (Retry(3, Immediate)) IntegrationFailure OperationOnly

    match Recovery.attempt allow Application at 1 false succeeds verified fault with
    | Recovery.Attempt attempted -> Assert.Equal(Succeeded, attempted.Outcome)
    | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``manual intervention is never attempted automatically`` () =
    // Requirement: additional 39.
    let performed = ref false

    let result =
        Recovery.attempt allow Agent at 1 true (fun _ ->
            performed.Value <- true
            Ok()) verified (faultWith ManualIntervention DataFailure ApplicationUnsafe)

    match result with
    | Recovery.Refused (Recovery.NeedsApproval _, _) -> ()
    | other -> failwith $"expected NeedsApproval, got {other}"

    Assert.False performed.Value

[<Fact>]
let ``a fault with no recovery does nothing`` () =
    match Recovery.attempt allow Application at 1 true succeeds verified (faultWith NoRecovery UnknownFailure OperationOnly) with
    | Recovery.Refused (Recovery.NothingToDo, _) -> ()
    | other -> failwith $"expected NothingToDo, got {other}"

// -------------------------------------------------------------------- auditing

[<Fact>]
let ``an attempt emits started and concluded events`` () =
    // Requirement: additional 37 -- automated remediation must be auditable.
    match Recovery.attempt allow Agent at 1 true succeeds verified (faultWith Reload IntegrationFailure OperationOnly) with
    | Recovery.Attempt attempted ->
        Assert.Equal(2, List.length attempted.Events)

        match attempted.Events with
        | [ RecoveryStarted (id, started); RecoveryConcluded (_, number, outcome, _) ] ->
            Assert.Equal(FaultId "F1", id)
            Assert.Equal(AwaitingVerification, started.Outcome)
            Assert.Equal(1, number)
            Assert.Equal(Succeeded, outcome)
        | other -> failwith $"unexpected events {other}"
    | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``the attempt records which actor initiated it`` () =
    // Requirement: additional 38.
    for actor in [ User; Application; Agent; ScheduledProcess; Integration; Operator ] do
        match Recovery.attempt allow actor at 1 true succeeds verified (faultWith Reload IntegrationFailure OperationOnly) with
        | Recovery.Attempt attempted -> Assert.Equal(actor, attempted.Attempt.Actor)
        | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``the attempt carries the fault's correlation id`` () =
    // Requirement: core 14.
    match Recovery.attempt allow Agent at 1 true succeeds verified (faultWith Reload IntegrationFailure OperationOnly) with
    | Recovery.Attempt attempted -> Assert.Equal(CorrelationId "CORR1", attempted.Attempt.CorrelationId)
    | other -> failwith $"expected an attempt, got {other}"

[<Fact>]
let ``attempts feed the lifecycle projection`` () =
    // Requirements: additional 31, 37 -- the projection is built from events.
    let fault = faultWith Reload IntegrationFailure OperationOnly

    match Recovery.attempt allow Agent at 1 true succeeds verified fault with
    | Recovery.Attempt attempted ->
        let projection = Lifecycle.project (FaultRecorded fault :: attempted.Events)
        let projected = projection.["F1"]
        Assert.Single projected.Attempts |> ignore
        Assert.Equal(Succeeded, projected.Attempts.Head.Outcome)
    | other -> failwith $"expected an attempt, got {other}"

// ------------------------------------------------------------------ capabilities

[<Fact>]
let ``capabilities expose only what the policy actually offers`` () =
    // Requirement: additional 28.
    Assert.Equal<Recovery.Capability list>([ Recovery.CanRetry ], Recovery.capabilities (faultWith (Retry(3, Immediate)) InfrastructureFailure OperationOnly))
    Assert.Equal<Recovery.Capability list>([ Recovery.CanReauthenticate ], Recovery.capabilities (faultWith RecoveryPolicy.Reauthenticate SecurityFailure FeatureUnavailable))
    Assert.Equal<Recovery.Capability list>([ Recovery.CanOpenReadOnly ], Recovery.capabilities (faultWith ReadOnlyRecovery DataFailure ApplicationUnsafe))
    Assert.Empty(Recovery.capabilities (faultWith ManualIntervention DataFailure ApplicationUnsafe))

// -------------------------------------------------------------------- safe mode

[<Fact>]
let ``corrupt data recommends read-only rather than carrying on`` () =
    // Requirement: additional 19.
    Assert.Equal(Some Recovery.ReadOnly, Recovery.recommendedMode (faultWith ReadOnlyRecovery DataFailure ApplicationUnsafe))

[<Fact>]
let ``an operation-scoped fault recommends no safe mode`` () =
    Assert.Equal(None, Recovery.recommendedMode (faultWith (Retry(3, Immediate)) IntegrationFailure OperationOnly))

[<Fact>]
let ``an unreachable dependency recommends offline mode`` () =
    Assert.Equal(Some Recovery.OfflineMode, Recovery.recommendedMode (faultWith (Retry(3, Immediate)) InfrastructureFailure FeatureUnavailable))

// ------------------------------------------------------------------ obligations

[<Fact>]
let ``authentication failure raises a reauthenticate obligation`` () =
    // Requirement: additional 16.
    match Recovery.raiseObligation at (faultWith RecoveryPolicy.Reauthenticate SecurityFailure FeatureUnavailable) with
    | Some obligation ->
        Assert.Equal(Recovery.Reauthenticate, obligation.Kind)
        Assert.True obligation.Discharged.IsNone
    | None -> failwith "expected an obligation"

[<Fact>]
let ``corrupt data raises an obligation to resolve it`` () =
    // Requirement: additional 39.
    match Recovery.raiseObligation at (faultWith ManualIntervention DataFailure ApplicationUnsafe) with
    | Some obligation -> Assert.Equal(Recovery.ResolveCorruptData, obligation.Kind)
    | None -> failwith "expected an obligation"

[<Fact>]
let ``a routine retryable fault raises no obligation`` () =
    Assert.True (Recovery.raiseObligation at (faultWith (Retry(3, Immediate)) IntegrationFailure OperationOnly)).IsNone

[<Fact>]
let ``obligations stay outstanding until explicitly discharged`` () =
    // Requirement: additional 16 -- visible until resolved or superseded.
    let obligation = (Recovery.raiseObligation at (faultWith ManualIntervention DataFailure ApplicationUnsafe)).Value
    Assert.Single(Recovery.outstanding [ obligation ]) |> ignore
    let discharged = Recovery.discharge (at.AddHours 2.) obligation
    Assert.Empty(Recovery.outstanding [ discharged ])
    Assert.True discharged.Discharged.IsSome
