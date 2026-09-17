namespace Aegis

open System

/// Redaction is applied before an event reaches any sink: a sink is never
/// responsible for deciding whether a credential is safe to persist.
/// Requirements: core 11, 12; additional 27, 40; logging 21.
module Redaction =

    [<Literal>]
    let Placeholder = "[redacted]"

    /// A rule decides, from a context key, whether the value must be removed
    /// regardless of its declared classification.
    type Rule =
        { Name: string
          AppliesTo: string -> bool }

    let private containsAny (needles: string list) (key: string) =
        let k = key.ToLowerInvariant()
        needles |> List.exists (fun n -> k.Contains n)

    /// Keys that must never be recorded. Requirements: core 12, logging 21.
    let defaultRules =
        [ { Name = "credentials"
            AppliesTo =
              containsAny
                  [ "token"; "password"; "passwd"; "secret"; "apikey"; "api-key"; "api_key"
                    "authorization"; "auth-header"; "cookie"; "session"; "privatekey"
                    "private-key"; "private_key"; "credential"; "bearer"; "signature" ] } ]

    /// Applications register additional rules; they are additive and never
    /// remove the defaults. Requirements: core 12, logging 21.
    let withRule rule rules = rule :: rules

    let private ruleHit rules key =
        rules |> List.tryFind (fun r -> r.AppliesTo key)

    /// Outcome of redacting one value, so suppression is observable rather
    /// than silent. Requirement: core 7 applied to redaction.
    type Decision =
        | Kept of string
        | Masked of reason: string
        | Dropped of reason: string

    /// Secret is never persisted. Sensitive is masked. A rule hit on the key
    /// drops the value whatever its classification, because a mislabelled
    /// credential is still a credential.
    let decide rules (key: string) (value: ContextValue) =
        match ruleHit rules key, value with
        | Some rule, _ -> Dropped $"rule:{rule.Name}"
        | None, Secret _ -> Dropped "classification:secret"
        | None, Sensitive _ -> Masked "classification:sensitive"
        | None, Public v -> Kept v
        | None, Internal v -> Kept v

    /// Redacted context ready for a sink: dropped keys are retained with the
    /// placeholder so a reader can see that something was removed.
    let apply rules (context: Map<string, ContextValue>) =
        context
        |> Map.map (fun key value ->
            match decide rules key value with
            | Kept v -> v
            | Masked _
            | Dropped _ -> Placeholder)

    /// Which keys were removed or masked, for diagnostics about redaction itself.
    let audit rules (context: Map<string, ContextValue>) =
        context
        |> Map.toList
        |> List.choose (fun (key, value) ->
            match decide rules key value with
            | Kept _ -> None
            | Masked reason -> Some(key, reason)
            | Dropped reason -> Some(key, reason))
