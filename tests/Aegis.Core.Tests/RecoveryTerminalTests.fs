module Aegis.Tests.RecoveryTerminal

// Retry exhaustion is a terminal failure and must be recorded as one
// (aegis#13 AEGIS-QUAL-005), not left to every caller to remember.

open System
open Xunit
open Aegis

let private at = DateTimeOffset(2026, 10, 5, 9, 0, 0, TimeSpan.Zero)

// ------------------------------------------------- characterization (red before the fix)

let private retryFault =
    { Id = FaultId "F1"
      CorrelationId = CorrelationId "CORR1"
      Timestamp = at
      Application = "Praxis"
      ApplicationVersion = None
      Operation = "Praxis.Remote.Fetch"
      Category = InfrastructureFailure
      Code = FaultCode "AEGIS.NETWORK.TIMEOUT"
      Severity = FaultSeverity.Warning
      Impact = OperationOnly
      Domain = EnvironmentDomain
      Radius = OneOperation
      Retention = DiagnosticOnly
      Persistence = Transient
      Owner = None
      Dependencies = [ "Praxis" ]
      UserMessage = "The remote call timed out."
      TechnicalDetails = None
      Context = Map.empty
      Recovery = Retry(3, Immediate)
      Diagnostics = noDiagnostics
      Cause = None }

let private allow = { Recovery.Authorize = fun _ _ -> Recovery.Authorized }

[<Fact>]
let ``exhausted recovery records an explicit terminal event`` () =
    match Recovery.attempt allow Application at 4 true (fun _ -> Ok()) (fun () -> Some true) retryFault with
    | Recovery.Refused (Recovery.AttemptsExhausted 3, events) ->
        match events with
        | [ RecoveryConcluded (id, 4, FailedWith reason, when') ] ->
            Assert.Equal(retryFault.Id, id)
            Assert.Equal(at, when')
            Assert.Contains("exhausted", reason)
        | other -> failwith $"expected one terminal RecoveryConcluded event, got {other}"
    | other -> failwith $"expected exhaustion, got {other}"

[<Fact>]
let ``refusing to repeat a non-idempotent action records an explicit terminal event`` () =
    match Recovery.attempt allow Application at 2 false (fun _ -> Ok()) (fun () -> Some true) retryFault with
    | Recovery.Refused (Recovery.UnsafeToRepeat, [ RecoveryConcluded (_, 2, FailedWith _, _) ]) -> ()
    | other -> failwith $"expected a terminal event, got {other}"

[<Fact>]
let ``a non-terminal refusal still carries no event`` () =
    // NothingToDo and approval/authorization refusals are not terminal
    // failures of a recovery that ran; they stay event-free.
    match Recovery.attempt Recovery.denyAll Application at 1 true (fun _ -> Ok()) (fun () -> Some true) retryFault with
    | Recovery.Refused (Recovery.NotAuthorized _, []) -> ()
    | other -> failwith $"expected an event-free refusal, got {other}"

// ------------------------------------------------------------------ prevention

[<Fact>]
let ``a refusal carries a terminal event exactly when it is terminal`` () =
    // Property over every refusal `attempt` can produce from these inputs.
    let authorities =
        [ allow
          Recovery.denyAll
          { Recovery.Authorize = fun _ _ -> Recovery.RequiresApproval "a human must decide" } ]

    let policies = [ Retry(3, Immediate); Reload; ManualIntervention; NoRecovery ]

    for authority in authorities do
        for policy in policies do
            for attemptNumber in 1..5 do
                for idempotent in [ true; false ] do
                    match
                        Recovery.attempt authority Application at attemptNumber idempotent (fun _ -> Ok()) (fun () -> Some true) { retryFault with Recovery = policy }
                    with
                    | Recovery.Refused (refusal, events) ->
                        Assert.True(
                            (Recovery.isTerminal refusal = not (List.isEmpty events)),
                            $"{refusal} with {policy} at attempt {attemptNumber}: events {events}"
                        )
                    | Recovery.Attempt _ -> ()
