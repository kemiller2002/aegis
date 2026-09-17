module Aegis.Tests.Translation

open System
open Xunit
open Aegis
open Aegis.Integration.GitHub

let private at = DateTimeOffset(2026, 9, 17, 9, 0, 0, TimeSpan.Zero)
let private identity = FaultId "F1", CorrelationId "CORR1", at

let private translate failure =
    Translation.toFault
        GitHubFailure.mapping
        identity
        ("Chrona", Some "1.4.2")
        "Chrona.TimeEntry.Load"
        (Map [ "repository", Public "aegis" ])
        None
        failure

// ------------------------------------------------- contract tests: status codes

[<Theory>]
[<InlineData(401)>]
[<InlineData(403)>]
let ``an unauthorized status becomes AuthenticationFailed`` status =
    // Requirement: additional 23.
    Assert.Equal(Some GitHubFailure.AuthenticationFailed, GitHubFailure.ofStatus "aegis" status None)

[<Fact>]
let ``a not-found status becomes RepositoryNotFound`` () =
    Assert.Equal(Some(GitHubFailure.RepositoryNotFound "aegis"), GitHubFailure.ofStatus "aegis" 404 None)

[<Fact>]
let ``a too-many-requests status becomes RateLimited carrying retry-after`` () =
    let retryAfter = Some(TimeSpan.FromSeconds 30.)
    Assert.Equal(Some(GitHubFailure.RateLimited retryAfter), GitHubFailure.ofStatus "aegis" 429 retryAfter)

[<Fact>]
let ``a conflict status becomes Conflict`` () =
    Assert.Equal(Some(GitHubFailure.Conflict "aegis"), GitHubFailure.ofStatus "aegis" 409 None)

[<Theory>]
[<InlineData(408)>]
[<InlineData(504)>]
let ``timeout statuses become Timeout`` status =
    Assert.Equal(Some GitHubFailure.Timeout, GitHubFailure.ofStatus "aegis" status None)

[<Theory>]
[<InlineData(502)>]
[<InlineData(503)>]
let ``gateway statuses become NetworkUnavailable`` status =
    Assert.Equal(Some GitHubFailure.NetworkUnavailable, GitHubFailure.ofStatus "aegis" status None)

[<Fact>]
let ``a success status is not a failure`` () =
    Assert.Equal(None, GitHubFailure.ofStatus "aegis" 200 None)

// -------------------------------------------- contract tests: exception leakage

[<Fact>]
let ``HttpRequestException does not escape the boundary`` () =
    // Requirement: core 16 -- the named example in the requirements.
    let translated = GitHubFailure.ofException (Net.Http.HttpRequestException "connection reset")
    Assert.Equal(GitHubFailure.NetworkUnavailable, translated)

[<Fact>]
let ``JsonException becomes InvalidResponse rather than a network failure`` () =
    // Requirement: core 16 -- a malformed body is not a connectivity problem.
    match GitHubFailure.ofException (Text.Json.JsonException "unexpected token") with
    | GitHubFailure.InvalidResponse detail -> Assert.Contains("malformed response", detail)
    | other -> failwith $"expected InvalidResponse, got {other}"

[<Fact>]
let ``TimeoutException becomes Timeout`` () =
    Assert.Equal(GitHubFailure.Timeout, GitHubFailure.ofException (TimeoutException()))

[<Fact>]
let ``an unrecognized exception still yields a typed failure`` () =
    // Nothing may cross the boundary untyped. Requirement: additional 23.
    match GitHubFailure.ofException (Exception "something odd") with
    | GitHubFailure.InvalidResponse _ -> ()
    | other -> failwith $"expected InvalidResponse, got {other}"

// -------------------------------------------------- normalization into a fault

[<Fact>]
let ``translation normalizes a typed failure into the shared fault model`` () =
    // Requirement: core 32.
    let fault = translate GitHubFailure.AuthenticationFailed
    Assert.Equal("AEGIS.GITHUB.AUTHENTICATION_FAILED", fault.Code.Value)
    Assert.Equal(SecurityFailure, fault.Category)
    Assert.Equal(Reauthenticate, fault.Recovery)
    Assert.Equal(Some "GitHubIntegration", fault.Owner)
    Assert.Equal("Chrona.TimeEntry.Load", fault.Operation)

[<Fact>]
let ``the user message carries no technical detail`` () =
    // Requirement: core 11.
    for failure in
        [ GitHubFailure.AuthenticationFailed
          GitHubFailure.NetworkUnavailable
          GitHubFailure.InvalidResponse "stack trace here at Foo.Bar line 42"
          GitHubFailure.Conflict "secret/path/to/file.json" ] do
        let fault = translate failure
        Assert.DoesNotContain("stack trace", fault.UserMessage)
        Assert.DoesNotContain("secret/path", fault.UserMessage)
        Assert.DoesNotContain("Exception", fault.UserMessage)

[<Fact>]
let ``translation preserves the original exception as the cause`` () =
    // Requirement: core 17 -- translation must not destroy diagnostics.
    let original = Net.Http.HttpRequestException "connection reset"

    let fault =
        Translation.toFault
            GitHubFailure.mapping
            identity
            ("Chrona", None)
            "Chrona.TimeEntry.Load"
            Map.empty
            (Some(
                CausedByException
                    { ExceptionType = original.GetType().FullName
                      Message = original.Message
                      StackTrace = None
                      Inner = None }
            ))
            (GitHubFailure.ofException original)

    match fault.Cause with
    | Some (CausedByException detail) ->
        Assert.Equal("System.Net.Http.HttpRequestException", detail.ExceptionType)
        Assert.Equal("connection reset", detail.Message)
    | other -> failwith $"expected the original exception, got {other}"

[<Fact>]
let ``transient and persistent failures are classified differently`` () =
    // Requirement: additional 18 -- drives retry and escalation.
    Assert.Equal(Transient, (translate GitHubFailure.NetworkUnavailable).Persistence)
    Assert.Equal(Persistent, (translate (GitHubFailure.RepositoryNotFound "aegis")).Persistence)
    Assert.Equal(RequiresIntervention, (translate GitHubFailure.AuthenticationFailed).Persistence)

[<Fact>]
let ``a conflict is never retried blindly`` () =
    // Requirement: core 21 -- a failed GET and a partial write differ.
    Assert.Equal(ManualIntervention, (translate (GitHubFailure.Conflict "path")).Recovery)

[<Fact>]
let ``rate limiting retries with the server's own retry-after when given`` () =
    match (translate (GitHubFailure.RateLimited(Some(TimeSpan.FromSeconds 30.)))).Recovery with
    | Retry (_, Fixed delay) -> Assert.Equal(TimeSpan.FromSeconds 30., delay)
    | other -> failwith $"expected a fixed backoff, got {other}"

[<Fact>]
let ``every GitHub failure has a distinct stable code`` () =
    // Requirement: core 4.
    let codes =
        [ GitHubFailure.AuthenticationFailed
          GitHubFailure.RepositoryNotFound "r"
          GitHubFailure.RateLimited None
          GitHubFailure.Conflict "p"
          GitHubFailure.NetworkUnavailable
          GitHubFailure.Timeout
          GitHubFailure.InvalidResponse "d" ]
        |> List.map (GitHubFailure.code >> fun c -> c.Value)

    Assert.Equal(List.length codes, codes |> List.distinct |> List.length)
    Assert.All(codes, fun c -> Assert.StartsWith("AEGIS.", c))

// --------------------------------------------------- integrity and migration

[<Fact>]
let ``migration failures are distinguishable from generic deserialization`` () =
    // Requirement: additional 24.
    let required = Integrity.Migration(Integrity.MigrationRequired("v1", "v2"))
    let mismatch = Integrity.Migration(Integrity.SchemaMismatch "field removed")
    Assert.Equal("AEGIS.SCHEMA.MIGRATION_REQUIRED", (Integrity.code required).Value)
    Assert.Equal("AEGIS.SCHEMA.MISMATCH", (Integrity.code mismatch).Value)
    Assert.NotEqual(Integrity.code required, Integrity.code mismatch)

[<Fact>]
let ``integrity recovery never proposes a write before correctness is established`` () =
    // Requirement: core 20.
    let noWrite =
        [ Integrity.InvalidPersistedState "bad"
          Integrity.HashMismatch("a", "b")
          Integrity.UnexpectedRepositoryStructure "odd"
          Integrity.Migration(Integrity.MigrationRequired("v1", "v2"))
          Integrity.Migration(Integrity.UnsupportedVersion "v9") ]

    for failure in noWrite do
        match Integrity.recovery failure with
        | ReadOnlyRecovery
        | ManualIntervention
        | NoRecovery -> ()
        | other -> failwith $"{failure} proposed a mutating recovery: {other}"

[<Fact>]
let ``corrupt state is treated as unsafe to continue`` () =
    // Requirements: core 20, 39.
    Assert.Equal(ApplicationUnsafe, Integrity.impact (Integrity.HashMismatch("a", "b")))
    Assert.Equal(ApplicationUnsafe, Integrity.impact (Integrity.InvalidPersistedState "bad"))
    Assert.Equal(FaultSeverity.Critical, (Integrity.mapping.Severity (Integrity.InvalidPersistedState "bad")))

[<Fact>]
let ``integrity failures are data failures and need intervention`` () =
    let fault =
        Translation.toFault
            Integrity.mapping
            identity
            ("Chrona", None)
            "Chrona.State.Load"
            Map.empty
            None
            (Integrity.HashMismatch("expected", "actual"))

    Assert.Equal(DataFailure, fault.Category)
    Assert.Equal(RequiresIntervention, fault.Persistence)
    Assert.Equal(ReadOnlyRecovery, fault.Recovery)

[<Fact>]
let ``read-only recovery survives serialization`` () =
    let collector = Sinks.Collector()

    let config =
        { Application = "Chrona"
          Version = None
          Sinks = [ collector.Sink() ]
          Rules = Redaction.defaultRules
          Fallback = ignore
          Persistence = Blocking
          Now = fun () -> at
          Random = fun () -> 1L, 2L }

    let fault =
        Translation.toFault Integrity.mapping identity ("Chrona", None) "Chrona.State.Load" Map.empty None (Integrity.InvalidPersistedState "bad")

    Aegis.report config (FaultRecorded fault) |> ignore
    Assert.Contains("\"recovery\":\"ReadOnlyRecovery\"", List.head collector.Events)
