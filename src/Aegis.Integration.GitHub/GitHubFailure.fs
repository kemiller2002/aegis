namespace Aegis.Integration.GitHub

open System
open Aegis

/// The GitHub integration assembly's own typed failure model, and the
/// translation that keeps technology exceptions from escaping the boundary.
///
/// This is the worked example the requirements describe: HttpRequestException
/// must not escape the GitHub boundary, and JsonException must not be
/// reported as if it were a network problem.
/// Requirements: core 16, 32; additional 23.
module GitHubFailure =

    /// Requirement: core 32 -- the integration assembly knows WHAT failed.
    type T =
        | AuthenticationFailed
        | RepositoryNotFound of repository: string
        | RateLimited of retryAfter: TimeSpan option
        | Conflict of path: string
        | NetworkUnavailable
        | Timeout
        | InvalidResponse of detail: string

    /// HTTP status to typed failure. Requirement: additional 23.
    let ofStatus (repository: string) (status: int) (retryAfter: TimeSpan option) =
        match status with
        | 401
        | 403 -> Some AuthenticationFailed
        | 404 -> Some(RepositoryNotFound repository)
        | 409 -> Some(Conflict repository)
        | 429 -> Some(RateLimited retryAfter)
        | 408
        | 504 -> Some Timeout
        | 502
        | 503 -> Some NetworkUnavailable
        | s when s >= 500 -> Some(InvalidResponse $"server returned {s}")
        | s when s >= 400 -> Some(InvalidResponse $"request rejected with {s}")
        | _ -> None

    /// Technology exception to typed failure. Anything unrecognized becomes
    /// InvalidResponse rather than leaking, so no raw exception type crosses
    /// the boundary. Requirements: core 16; additional 23.
    let ofException (ex: exn) =
        match ex with
        | :? TimeoutException -> Timeout
        | :? Net.Http.HttpRequestException -> NetworkUnavailable
        | :? Text.Json.JsonException as json -> InvalidResponse $"malformed response: {json.Message}"
        | :? UriFormatException as uri -> InvalidResponse $"invalid request target: {uri.Message}"
        | other -> InvalidResponse other.Message

    let code =
        function
        | AuthenticationFailed -> FaultCode "AEGIS.GITHUB.AUTHENTICATION_FAILED"
        | RepositoryNotFound _ -> FaultCode "AEGIS.GITHUB.REPOSITORY_NOT_FOUND"
        | RateLimited _ -> FaultCode "AEGIS.GITHUB.RATE_LIMITED"
        | Conflict _ -> FaultCode "AEGIS.GITHUB.CONFLICT"
        | NetworkUnavailable -> FaultCode "AEGIS.NETWORK.UNAVAILABLE"
        | Timeout -> FaultCode "AEGIS.NETWORK.TIMEOUT"
        | InvalidResponse _ -> FaultCode "AEGIS.GITHUB.INVALID_RESPONSE"

    /// Retry is offered only where repeating the call is safe. A conflict is
    /// never retried blindly. Requirement: core 21.
    let recovery =
        function
        | AuthenticationFailed -> Reauthenticate
        | RepositoryNotFound _ -> ManualIntervention
        | RateLimited retryAfter ->
            Retry(3, retryAfter |> Option.map Fixed |> Option.defaultValue (Exponential(TimeSpan.FromSeconds 2.)))
        | Conflict _ -> ManualIntervention
        | NetworkUnavailable
        | Timeout -> Retry(3, Exponential(TimeSpan.FromSeconds 1.))
        | InvalidResponse _ -> NoRecovery

    let persistence =
        function
        | NetworkUnavailable
        | Timeout
        | RateLimited _ -> Transient
        | AuthenticationFailed -> RequiresIntervention
        | RepositoryNotFound _
        | Conflict _ -> Persistent
        | InvalidResponse _ -> UnknownPersistence

    let category =
        function
        | AuthenticationFailed -> SecurityFailure
        | NetworkUnavailable
        | Timeout -> InfrastructureFailure
        | RepositoryNotFound _
        | Conflict _
        | RateLimited _
        | InvalidResponse _ -> IntegrationFailure

    /// User-facing text: no tokens, no URLs, no internal detail.
    /// Requirement: core 11.
    let userMessage =
        function
        | AuthenticationFailed -> "GitHub sign-in is required."
        | RepositoryNotFound _ -> "The repository could not be found."
        | RateLimited _ -> "GitHub is rate limiting requests. Try again shortly."
        | Conflict _ -> "The change conflicts with something already saved."
        | NetworkUnavailable -> "GitHub could not be reached."
        | Timeout -> "GitHub did not respond in time."
        | InvalidResponse _ -> "GitHub returned a response that could not be read."

    /// Requirement: core 32 -- Aegis normalizes the typed failure.
    let mapping: Translation.Mapping<T> =
        { Code = code
          Category = category
          Severity =
            (function
            | AuthenticationFailed -> FaultSeverity.Error
            | InvalidResponse _ -> FaultSeverity.Error
            | _ -> FaultSeverity.Warning)
          Impact =
            (function
            | AuthenticationFailed -> FeatureUnavailable
            | RepositoryNotFound _ -> FeatureUnavailable
            | _ -> OperationOnly)
          Persistence = persistence
          Recovery = recovery
          UserMessage = userMessage
          Owner = "GitHubIntegration"
          // The chain the requirements' own example describes:
          // Chrona -> GitHub Integration -> GitHub API. Requirement: additional 45.
          Dependencies = [ "GitHubIntegration"; "GitHubApi" ]
          // Where the failure sits, and how far it reaches.
          // Requirements: additional 43, 44.
          Domain =
            (function
            | AuthenticationFailed -> ExternalDependency
            | RepositoryNotFound _ -> RepositoryDomain
            | NetworkUnavailable
            | Timeout -> EnvironmentDomain
            | RateLimited _
            | Conflict _
            | InvalidResponse _ -> IntegrationDomain)
          Radius =
            (function
            // Sign-in is gone for the whole session, not one call.
            | AuthenticationFailed -> OneSession
            | RepositoryNotFound _ -> OneRepository
            | RateLimited _ -> OneFeature
            | Conflict _ -> OneItem
            | NetworkUnavailable
            | Timeout
            | InvalidResponse _ -> OneOperation)
          Retention =
            (function
            // A security-relevant failure is audit material; a timeout is not.
            | AuthenticationFailed -> AuditRequired
            | Conflict _ -> RetainDays 90
            | _ -> DiagnosticOnly) }
