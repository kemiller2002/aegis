namespace Aegis

open System
open System.Globalization
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions

/// Who discovered, remediated and validated a fault, in which run, and what
/// it was derived from.
///
/// The shapes are the Praxis agent-provenance contract, implemented locally
/// so the core keeps no dependency on Praxis: the actor
/// (`kind,id,provider,model,runtime`), execution-keyed contributions, and the
/// `praxis.provenance-record` interchange record with lineage. Praxis owns
/// the contract (RQ-ROS-2026-A001, A004, A013, A014, A015); this module does
/// not redefine it, it reads and writes it losslessly.
///
/// Identity here is self-reported provenance. It is not authentication, not
/// authorization, and not evidence or evidence weight.
/// Requirements: AEG-PROV-001, 002, 003, 004, 005, 007; additional 38.
module Provenance =

    let private regex (pattern: string) = Regex(pattern, RegexOptions.CultureInvariant)

    /// Recognizes unambiguous credential shapes so a value that would leak one
    /// is refused rather than recorded. A guard against accidents, not a
    /// secret scanner. Requirement: AEG-PROV-005.
    module Credentials =
        let private patterns =
            [ @"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}"
              @"\bgh[pousr]_[A-Za-z0-9]{20,}"
              @"\bgithub_pat_[A-Za-z0-9_]{20,}"
              @"\bxox[abposr]-[A-Za-z0-9-]{10,}"
              @"\bAKIA[0-9A-Z]{16}\b"
              @"\bAIza[0-9A-Za-z_-]{30,}"
              @"-----BEGIN [A-Z ]*PRIVATE KEY-----"
              @"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"
              @"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
              @"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password|passwd)\s*[=:]\s*\S{8,}" ]
            |> List.map regex

        let looksLikeCredential (value: string) =
            not (isNull value) && patterns |> List.exists (fun pattern -> pattern.IsMatch value)

    // ------------------------------------------------------------------ actor

    /// agent: an AI system; automation: a deterministic non-agent process
    /// such as CI; unknown is recorded honestly rather than guessed; `x-...`
    /// is a namespaced extension. Requirement: AEG-PROV-001.
    [<RequireQualifiedAccess>]
    type ActorKind =
        | Agent
        | Human
        | Automation
        | Unknown
        | Extension of string

    [<RequireQualifiedAccess>]
    module ActorKind =
        let private extension = regex "^x-[a-z0-9][a-z0-9-]*$"

        let code =
            function
            | ActorKind.Agent -> "agent"
            | ActorKind.Human -> "human"
            | ActorKind.Automation -> "automation"
            | ActorKind.Unknown -> "unknown"
            | ActorKind.Extension value -> value

        let tryParse (value: string) =
            match value with
            | "agent" -> Some ActorKind.Agent
            | "human" -> Some ActorKind.Human
            | "automation" -> Some ActorKind.Automation
            | "unknown" -> Some ActorKind.Unknown
            | other when not (isNull other) && extension.IsMatch other -> Some(ActorKind.Extension other)
            | _ -> None

    /// The stable identity of whoever acted. `Provider`/`Model`/`Runtime` are
    /// `None` when not applicable (a human) and `Some "unknown"` when
    /// applicable but not known; the two are never conflated.
    /// Requirement: AEG-PROV-001.
    type Actor =
        { Kind: ActorKind
          Id: string
          Provider: string option
          Model: string option
          Runtime: string option }

    [<RequireQualifiedAccess>]
    module Actor =
        [<Literal>]
        let UnknownValue = "unknown"

        let private orUnknown (value: string) =
            if String.IsNullOrWhiteSpace value then UnknownValue else value.Trim()

        let private known (value: string) =
            not (String.IsNullOrWhiteSpace value) && value.Trim() <> UnknownValue

        /// A non-human actor always states provider, model and runtime, as
        /// "unknown" when not known.
        let nonHuman kind id provider model runtime =
            { Kind = kind
              Id = orUnknown id
              Provider = Some(orUnknown provider)
              Model = Some(orUnknown model)
              Runtime = Some(orUnknown runtime) }

        let agent id provider model runtime = nonHuman ActorKind.Agent id provider model runtime

        let automation id provider model runtime = nonHuman ActorKind.Automation id provider model runtime

        /// A human: provider, model and runtime do not apply and are omitted.
        let human id =
            { Kind = ActorKind.Human
              Id = orUnknown id
              Provider = None
              Model = None
              Runtime = None }

        let unknown = nonHuman ActorKind.Unknown "" "" "" ""

        /// CI under GitHub Actions with nothing declared.
        let githubActions = automation "github/github-actions" "github" UnknownValue "github-actions"

        /// Structural problems as (field, message). An agent must state
        /// provider, model and runtime; no field may carry a credential.
        let problems (actor: Actor) : (string * string) list =
            [ if String.IsNullOrWhiteSpace actor.Id then
                  "id", "actor id must not be empty; use 'unknown' when it is not known"
              match actor.Kind with
              | ActorKind.Extension value when ActorKind.tryParse value <> Some actor.Kind ->
                  "kind", $"invalid actor kind '{value}'"
              | ActorKind.Agent ->
                  for field, value in [ "provider", actor.Provider; "model", actor.Model; "runtime", actor.Runtime ] do
                      match value with
                      | None -> field, $"an agent must record {field} (use 'unknown' when it is not known)"
                      | Some text when String.IsNullOrWhiteSpace text -> field, $"agent {field} must not be empty"
                      | Some _ -> ()
              | _ -> ()
              for field, value in [ "id", Some actor.Id; "provider", actor.Provider; "model", actor.Model; "runtime", actor.Runtime ] do
                  match value with
                  | Some text when Credentials.looksLikeCredential text ->
                      field, "value looks like a credential; identity must never carry secrets"
                  | _ -> () ]

        /// Two records describe the same actor when kind, id and every
        /// applicable, known attribute agree; "unknown" contradicts nothing.
        let agrees (left: Actor) (right: Actor) =
            let compatible (a: string option) (b: string option) =
                match a, b with
                | Some x, Some y when known x && known y -> x = y
                | _ -> true

            left.Kind = right.Kind
            && (left.Id = right.Id || not (known left.Id) || not (known right.Id))
            && compatible left.Provider right.Provider
            && compatible left.Model right.Model
            && compatible left.Runtime right.Runtime

        let describe (actor: Actor) =
            let detail =
                match [ actor.Provider; actor.Model; actor.Runtime ] |> List.choose id with
                | [] -> ""
                | values -> " (" + String.concat ", " values + ")"

            $"{ActorKind.code actor.Kind}:{actor.Id}{detail}"

        /// The only environment keys identity is read from: whitelisted and
        /// non-secret. `GITHUB_ACTIONS` is consulted only to recognize CI.
        let environmentKeys =
            [ "ROS_ACTOR_KIND"; "ROS_ACTOR"; "ROS_TELEMETRY_PROVIDER"; "ROS_TELEMETRY_MODEL"; "ROS_TELEMETRY_RUNTIME" ]

        /// Resolve the acting identity from the whitelisted environment, as
        /// Praxis propagates it (`ros provenance identity --env`). Nothing is
        /// guessed: an undeclared attribute is "unknown". `lookup` is passed
        /// in, so this is pure; use `Environment.GetEnvironmentVariable`
        /// wrapped in an option at the edge. Requirement: AEG-PROV-001.
        let fromEnvironment (lookup: string -> string option) : Result<Actor, string list> =
            let read key =
                lookup key |> Option.map (fun (value: string) -> value.Trim()) |> Option.filter (fun value -> value <> "")

            let declared = environmentKeys |> List.exists (read >> Option.isSome)

            let resolved =
                if not declared && read "GITHUB_ACTIONS" = Some "true" then
                    Ok githubActions
                else
                    let kind =
                        match read "ROS_ACTOR_KIND" with
                        | None -> Ok ActorKind.Unknown
                        | Some text ->
                            match ActorKind.tryParse text with
                            | Some kind -> Ok kind
                            | None -> Error [ "ROS_ACTOR_KIND must be agent, human, automation, unknown or x-<extension>" ]

                    kind
                    |> Result.map (fun kind ->
                        let provider = read "ROS_TELEMETRY_PROVIDER" |> Option.defaultValue UnknownValue
                        let runtime = read "ROS_TELEMETRY_RUNTIME" |> Option.defaultValue UnknownValue

                        let id =
                            match read "ROS_ACTOR" with
                            | Some explicitId -> explicitId
                            | None when kind <> ActorKind.Human && known provider && known runtime -> $"{provider}/{runtime}"
                            | None -> UnknownValue

                        match kind with
                        | ActorKind.Human -> human id
                        | _ -> nonHuman kind id provider (read "ROS_TELEMETRY_MODEL" |> Option.defaultValue UnknownValue) runtime)

            resolved
            |> Result.bind (fun actor ->
                match problems actor with
                | [] -> Ok actor
                | found -> Error(found |> List.map (fun (field, message) -> $"actor.{field}: {message}")))

    // -------------------------------------------------------------- execution

    /// Contribution keys. A Praxis-propagated execution (`ROS_EXECUTION_ID`)
    /// wins; otherwise Aegis keys its own run as `EXE-aegis.<run>`, which can
    /// never collide with or impersonate a Praxis `EXE-<timestamp>-<random>`;
    /// a human or automation acting outside any run uses `CTB-<reference>`.
    /// Aegis never mints a Praxis-shaped execution id. Requirement: AEG-PROV-001.
    [<RequireQualifiedAccess>]
    module Execution =
        [<Literal>]
        let EnvironmentKey = "ROS_EXECUTION_ID"

        [<Literal>]
        let SystemName = "aegis"

        let private executionPattern = regex "^EXE-[A-Za-z0-9._-]+$"
        let private contributionPattern = regex "^CTB-[A-Za-z0-9._-]+$"
        let private systemPattern = regex "^[a-z][a-z0-9-]*$"
        let private runPattern = regex "^[A-Za-z0-9_-][A-Za-z0-9._-]*$"

        let isExecution (key: string) = not (isNull key) && executionPattern.IsMatch key

        let isContribution (key: string) = not (isNull key) && contributionPattern.IsMatch key

        let isKey key = isExecution key || isContribution key

        /// `EXE-<system>.<run>` for a system with no propagated Praxis execution.
        let foreign (system: string) (run: string) : Result<string, string> =
            if isNull system || not (systemPattern.IsMatch system) then
                Error "system must match ^[a-z][a-z0-9-]*$"
            elif isNull run || not (runPattern.IsMatch run) then
                Error "run must match ^[A-Za-z0-9_-][A-Za-z0-9._-]*$"
            else
                Ok $"EXE-{system}.{run}"

        /// Aegis's own run, namespaced as `EXE-aegis.<run>`.
        let ofRun (run: string) = foreign SystemName run

        /// `ROS_EXECUTION_ID` when Praxis propagated one, else Aegis's own run.
        let fromEnvironment (lookup: string -> string option) (run: string) : Result<string, string> =
            match lookup EnvironmentKey |> Option.map (fun (value: string) -> value.Trim()) |> Option.filter (fun value -> value <> "") with
            | Some propagated when isExecution propagated && not (Credentials.looksLikeCredential propagated) -> Ok propagated
            | Some _ -> Error $"{EnvironmentKey} is set but is not an execution id (EXE-...)"
            | None -> ofRun run

        /// A human or automation acting outside any run.
        let outsideRun (reference: string) : Result<string, string> =
            let key = "CTB-" + reference

            if isContribution key && not (Credentials.looksLikeCredential key) then
                Ok key
            else
                Error "a contribution reference must match ^[A-Za-z0-9._-]+$"

    // ------------------------------------------------------------ attribution

    /// Who performed one act, in which run, why, and on what evidence.
    ///
    /// `IdentifyHuman` is the additional-38 switch: a human's id is written
    /// as the redaction placeholder unless the caller states that
    /// identifying the individual is necessary. Agents and automation are
    /// not individuals and are always identified.
    /// Requirements: AEG-PROV-002, 005; additional 38.
    type Attribution =
        { Actor: Actor
          Execution: string
          Reason: string option
          Evidence: string list
          IdentifyHuman: bool }

    [<RequireQualifiedAccess>]
    module Attribution =
        let problems (attribution: Attribution) : string list =
            [ yield! Actor.problems attribution.Actor |> List.map (fun (field, message) -> $"actor.{field}: {message}")
              if not (Execution.isKey attribution.Execution) then
                  "execution: must be an execution (EXE-...) or contribution (CTB-...) key"
              elif Credentials.looksLikeCredential attribution.Execution then
                  "execution: looks like a credential"
              if attribution.Actor.Kind = ActorKind.Agent && not (Execution.isExecution attribution.Execution) then
                  "execution: an agent must be keyed by the execution (EXE-...) that produced its work"
              if attribution.Reason |> Option.exists Credentials.looksLikeCredential then
                  "reason: looks like a credential; provenance must never carry secrets"
              if attribution.Evidence |> List.exists String.IsNullOrWhiteSpace then
                  "evidence: references must not be empty"
              if attribution.Evidence |> List.exists Credentials.looksLikeCredential then
                  "evidence: a reference looks like a credential; provenance must never carry secrets" ]

        let private validated attribution =
            match problems attribution with
            | [] -> Ok attribution
            | found -> Error found

        /// A validated attribution with no reason or evidence.
        let create (actor: Actor) (execution: string) : Result<Attribution, string list> =
            validated
                { Actor = actor
                  Execution = execution
                  Reason = None
                  Evidence = []
                  IdentifyHuman = false }

        /// A reason is a single line.
        let withReason (reason: string) (attribution: Attribution) =
            { attribution with Reason = Some(reason.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ')) }

        let withEvidence (evidence: string list) (attribution: Attribution) =
            { attribution with Evidence = attribution.Evidence @ evidence |> List.distinct }

        /// State that identifying this human is necessary. Requirement: additional 38.
        let identified (attribution: Attribution) = { attribution with IdentifyHuman = true }

        /// The actor exactly as Aegis writes it anywhere: a human's id is
        /// withheld unless identified. Requirement: AEG-PROV-005.
        let recordedActor (attribution: Attribution) =
            match attribution.Actor.Kind with
            | ActorKind.Human when not attribution.IdentifyHuman -> { attribution.Actor with Id = Redaction.Placeholder }
            | _ -> attribution.Actor

    /// UTC, millisecond precision: the Aegis and Praxis timestamp form.
    let timestamp (at: DateTimeOffset) =
        at.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture)

    /// JSON forms of the actor and attribution. The actor's keys are always
    /// written in contract order: kind, id, provider, model, runtime.
    module Json =
        let writeActor (writer: Utf8JsonWriter) (actor: Actor) =
            writer.WriteStartObject()
            writer.WriteString("kind", ActorKind.code actor.Kind)
            writer.WriteString("id", actor.Id)

            for name, value in [ "provider", actor.Provider; "model", actor.Model; "runtime", actor.Runtime ] do
                value |> Option.iter (fun (text: string) -> writer.WriteString(name, text))

            writer.WriteEndObject()

        /// `{"execution":..,"actor":{..},"reason"?:..,"evidence"?:[..]}`,
        /// with the human-privacy rule applied to the actor.
        let writeAttribution (writer: Utf8JsonWriter) (attribution: Attribution) =
            writer.WriteStartObject()
            writer.WriteString("execution", attribution.Execution)
            writer.WritePropertyName "actor"
            writeActor writer (Attribution.recordedActor attribution)
            attribution.Reason |> Option.iter (fun reason -> writer.WriteString("reason", reason))

            match attribution.Evidence with
            | [] -> ()
            | evidence ->
                writer.WritePropertyName "evidence"
                writer.WriteStartArray()
                evidence |> List.iter (fun (item: string) -> writer.WriteStringValue item)
                writer.WriteEndArray()

            writer.WriteEndObject()

        let private text (element: JsonElement) (name: string) =
            match element.TryGetProperty name with
            | true, value when value.ValueKind = JsonValueKind.String -> Some(value.GetString())
            | _ -> None

        let tryReadActor (element: JsonElement) : Result<Actor, string> =
            if element.ValueKind <> JsonValueKind.Object then
                Error "actor must be an object"
            else
                match text element "kind" |> Option.bind ActorKind.tryParse with
                | None -> Error "actor.kind is missing or outside the vocabulary"
                | Some kind ->
                    Ok
                        { Kind = kind
                          Id = text element "id" |> Option.defaultValue ""
                          Provider = text element "provider"
                          Model = text element "model"
                          Runtime = text element "runtime" }

        /// Read an attribution back from a stored payload.
        let tryReadAttribution (element: JsonElement) : Result<Attribution, string list> =
            if element.ValueKind <> JsonValueKind.Object then
                Error [ "attribution must be an object" ]
            else
                let actor =
                    match element.TryGetProperty "actor" with
                    | true, value -> tryReadActor value
                    | _ -> Error "actor is required"

                let evidence =
                    match element.TryGetProperty "evidence" with
                    | true, value when value.ValueKind = JsonValueKind.Array ->
                        value.EnumerateArray()
                        |> Seq.map (fun item -> if item.ValueKind = JsonValueKind.String then item.GetString() else "")
                        |> Seq.toList
                    | _ -> []

                match actor with
                | Error message -> Error [ message ]
                | Ok actor ->
                    let attribution =
                        { Actor = actor
                          Execution = text element "execution" |> Option.defaultValue ""
                          Reason = text element "reason"
                          Evidence = evidence
                          IdentifyHuman = actor.Kind = ActorKind.Human && actor.Id <> Redaction.Placeholder }

                    match Attribution.problems attribution with
                    | [] -> Ok attribution
                    | found -> Error found

    // ----------------------------------------------------- interchange record

    /// A structural problem, attributed to a dotted field path.
    type Problem = { Field: string; Message: string }

    let private problem field message = { Field = field; Message = message }

    /// Praxis contribution operations, plus the documented interchange
    /// extensions. `x-reopened` is Aegis's own extension: reopening is not a
    /// synonym of any documented operation. Requirement: AEG-PROV-004.
    [<RequireQualifiedAccess>]
    module Operation =
        [<Literal>]
        let Created = "created"

        [<Literal>]
        let Modified = "modified"

        [<Literal>]
        let Reviewed = "reviewed"

        [<Literal>]
        let Approved = "approved"

        [<Literal>]
        let Superseded = "superseded"

        [<Literal>]
        let Migrated = "migrated"

        [<Literal>]
        let Handled = "x-handled"

        [<Literal>]
        let Resolved = "x-resolved"

        [<Literal>]
        let Remediated = "x-remediated"

        [<Literal>]
        let Validated = "x-validated"

        [<Literal>]
        let Dismissed = "x-dismissed"

        [<Literal>]
        let Reopened = "x-reopened"

        let private pattern =
            regex "^(created|modified|reviewed|approved|superseded|migrated|x-[a-z0-9][a-z0-9-]*)$"

        let isValid (operation: string) = not (isNull operation) && pattern.IsMatch operation

    /// One execution's contribution to a subject, exactly the Praxis entry.
    type Contribution =
        { Key: string
          Operations: string list
          At: string
          Last: string option
          Actor: Actor
          Reason: string option
          Evidence: string list }

    [<RequireQualifiedAccess>]
    module Contribution =
        let private timestampPattern =
            regex "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"

        let private parseInstant (value: string) =
            DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal)

        let isTimestamp (value: string) =
            not (isNull value) && timestampPattern.IsMatch value && fst (parseInstant value)

        /// Invalid timestamps sort last, so they never pose as the origin.
        let instantOf (value: string) =
            match parseInstant value with
            | true, parsed when isTimestamp value -> parsed
            | _ -> DateTimeOffset.MaxValue

        let instant (contribution: Contribution) = instantOf contribution.At

        let isCreation (contribution: Contribution) =
            contribution.Operations |> List.contains Operation.Created

        /// The contribution an attribution makes, with the privacy rule applied.
        let ofAttribution (operation: string) (at: DateTimeOffset) (attribution: Attribution) =
            { Key = attribution.Execution
              Operations = [ operation ]
              At = timestamp at
              Last = None
              Actor = Attribution.recordedActor attribution
              Reason = attribution.Reason
              Evidence = attribution.Evidence }

        let problems (contribution: Contribution) : (string * string) list =
            [ if not (Execution.isKey contribution.Key) then
                  "key", "a contribution key must be an execution (EXE-...) or contribution (CTB-...) ID"
              if contribution.Operations.IsEmpty then
                  "operations", "a contribution must record at least one operation"
              for operation in contribution.Operations do
                  if not (Operation.isValid operation) then
                      "operations", $"unknown operation '{operation}'"
              if List.length (List.distinct contribution.Operations) <> List.length contribution.Operations then
                  "operations", "operations must be unique"
              if not (isTimestamp contribution.At) then
                  "at", "'at' is not an ISO-8601 UTC timestamp"
              match contribution.Last with
              | Some last when not (isTimestamp last) -> "last", "'last' is not an ISO-8601 UTC timestamp"
              | Some last when instantOf last < instant contribution -> "last", "'last' must not precede 'at'"
              | _ -> ()
              yield! Actor.problems contribution.Actor |> List.map (fun (field, message) -> $"actor.{field}", message)
              if contribution.Actor.Kind = ActorKind.Agent && not (Execution.isExecution contribution.Key) then
                  "key", "an agent contribution must be keyed by the execution (EXE-...) that produced it"
              if contribution.Evidence |> List.exists String.IsNullOrWhiteSpace then
                  "evidence", "evidence references must not be empty"
              if contribution.Reason |> Option.exists Credentials.looksLikeCredential then
                  "reason", "looks like a credential; provenance must never carry secrets"
              if contribution.Evidence |> List.exists Credentials.looksLikeCredential then
                  "evidence", "a reference looks like a credential; provenance must never carry secrets" ]

    /// A semantic contract version. Any minor or patch of major 1 is read.
    type ContractVersion = { Major: int; Minor: int; Patch: int }

    [<RequireQualifiedAccess>]
    module ContractVersion =
        let private pattern = regex "^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"

        let current = { Major = 1; Minor = 0; Patch = 0 }

        let code (version: ContractVersion) = $"{version.Major}.{version.Minor}.{version.Patch}"

        let tryParse (value: string) =
            if isNull value then
                None
            else
                let matched = pattern.Match value

                if not matched.Success then
                    None
                else
                    match Int32.TryParse matched.Groups[1].Value, Int32.TryParse matched.Groups[2].Value, Int32.TryParse matched.Groups[3].Value with
                    | (true, major), (true, minor), (true, patch) -> Some { Major = major; Minor = minor; Patch = patch }
                    | _ -> None

        let isSupported (version: ContractVersion) = version.Major = current.Major

    /// The interpreted interchange record. Unknown fields are not modelled
    /// here; they live in the verbatim `Document` text and are never lost.
    type Record =
        { Version: ContractVersion
          Subject: string option
          Contributions: Contribution list
          DerivedFrom: string list
          Sources: (string * Snapshot) list }

    /// A lineage snapshot: the source's own provenance. An unsupported major
    /// is opaque: carried, never interpreted.
    and [<RequireQualifiedAccess>] Snapshot =
        | Known of Record
        | Opaque of version: string

    /// How a record read. Requirement: AEG-PROV-003.
    [<RequireQualifiedAccess>]
    type Reading =
        /// contract and version present, supported major.
        | Current of Record
        /// A bare `{"contributions": ...}` block: legacy version 1.
        | Unversioned of Record
        /// A major this codec does not support: carried verbatim only.
        | Unsupported of version: string

    [<RequireQualifiedAccess>]
    module Record =
        [<Literal>]
        let ContractName = "praxis.provenance-record"

        [<Literal>]
        let MaxSourceDepth = 16

        let private referencePattern = regex "^\S+$"

        let originator (record: Record) =
            record.Contributions |> List.tryFind Contribution.isCreation

        let private creationProblems (contributions: Contribution list) =
            match contributions |> List.filter Contribution.isCreation with
            | [] -> []
            | [ creation ] ->
                contributions
                |> List.filter (fun item -> Contribution.instant item < Contribution.instant creation)
                |> List.map (fun item ->
                    problem $"contributions.{item.Key}.at" $"contribution precedes the recorded creation ({creation.Key})")
            | many ->
                [ problem "contributions" ("more than one contribution claims 'created': " + (many |> List.map _.Key |> String.concat ", ")) ]

        let rec private problemsAt (prefix: string) (depth: int) (record: Record) : Problem list =
            let at field = if prefix = "" then field else $"{prefix}.{field}"

            let contributionProblems =
                record.Contributions
                |> List.collect (fun contribution ->
                    Contribution.problems contribution
                    |> List.map (fun (field, message) -> problem (at $"contributions.{contribution.Key}.{field}") message))

            let references =
                (record.Subject |> Option.map (fun value -> "subject", value) |> Option.toList)
                @ (record.DerivedFrom |> List.map (fun value -> "derivedFrom", value))

            let referenceProblems =
                references
                |> List.collect (fun (field, value) ->
                    [ if isNull value || not (referencePattern.IsMatch value) then
                          problem (at field) $"reference '{value}' must be a non-empty token without whitespace"
                      if Credentials.looksLikeCredential value then
                          problem (at field) "a reference looks like a credential; provenance must never carry secrets" ])

            let lineageProblems =
                [ match record.Subject with
                  | Some subject when List.contains subject record.DerivedFrom ->
                      problem (at "derivedFrom") $"'{subject}' cannot be derived from itself"
                  | _ -> ()
                  if List.length (List.distinct record.DerivedFrom) <> List.length record.DerivedFrom then
                      problem (at "derivedFrom") "lineage references must be unique"
                  for reference, snapshot in record.Sources do
                      if not (List.contains reference record.DerivedFrom) then
                          problem (at $"sources.{reference}") "a lineage snapshot must name a reference listed in derivedFrom"
                      match snapshot with
                      | Snapshot.Known source when source.Subject.IsSome && source.Subject <> Some reference ->
                          problem (at $"sources.{reference}.subject") "a lineage snapshot must be the named source's own provenance"
                      | _ -> () ]

            let sourceProblems =
                record.Sources
                |> List.collect (fun (reference, snapshot) ->
                    match snapshot with
                    | Snapshot.Opaque _ -> []
                    | Snapshot.Known _ when depth >= MaxSourceDepth ->
                        [ problem (at $"sources.{reference}") $"lineage snapshots nest deeper than {MaxSourceDepth} levels" ]
                    | Snapshot.Known source -> problemsAt (at $"sources.{reference}") (depth + 1) source)

            contributionProblems
            @ (creationProblems record.Contributions |> List.map (fun item -> { item with Field = at item.Field }))
            @ referenceProblems
            @ lineageProblems
            @ sourceProblems

        /// Every structural rule, recursively through lineage snapshots. Empty
        /// means well-formed; it says nothing about whether identities are true.
        let problems (record: Record) = problemsAt "" 0 record

        /// Merge a contribution under the append-only rules: extend the same
        /// execution's own entry only when the actor agrees; never
        /// re-attribute; at most one `created`, and nothing before it.
        let merge (contribution: Contribution) (record: Record) : Result<Contribution, string> =
            match record.Contributions |> List.tryFind (fun existing -> existing.Key = contribution.Key) with
            | Some existing when not (Actor.agrees existing.Actor contribution.Actor) ->
                Error
                    $"contribution '{contribution.Key}' is attributed to {Actor.describe existing.Actor}; refusing to re-attribute it to {Actor.describe contribution.Actor}"
            | Some existing ->
                let union (left: string list) (right: string list) =
                    left @ (right |> List.filter (fun item -> not (List.contains item left)))

                let latestSoFar = existing.Last |> Option.defaultValue existing.At

                Ok
                    { existing with
                        Operations = union existing.Operations contribution.Operations
                        Evidence = union existing.Evidence contribution.Evidence
                        Last =
                            if Contribution.instant contribution > Contribution.instantOf latestSoFar then
                                Some contribution.At
                            else
                                existing.Last
                        Reason = existing.Reason |> Option.orElse contribution.Reason }
            | None when Contribution.isCreation contribution && (originator record).IsSome ->
                Error "the subject already has a recorded originator; a later contribution cannot claim 'created'"
            | None when
                Contribution.isCreation contribution
                && record.Contributions |> List.exists (fun item -> Contribution.instant item < Contribution.instant contribution)
                ->
                Error "a 'created' contribution cannot follow existing contributions"
            | None -> Ok contribution

        /// One-hop destructive-change check over the interpreted record:
        /// nothing removed, no actor overwritten, no `at` changed, no
        /// operation or evidence removed, no reason rewritten, no originator
        /// changed, no lineage removed, no major changed, no version lowered.
        let successorProblems (before: Record) (after: Record) : Problem list =
            let afterByKey = after.Contributions |> List.map (fun item -> item.Key, item) |> Map.ofList

            let contributionProblems =
                before.Contributions
                |> List.collect (fun previous ->
                    let field name = $"contributions.{previous.Key}{name}"

                    match afterByKey |> Map.tryFind previous.Key with
                    | None -> [ problem (field "") "contribution was removed; provenance history is append-only" ]
                    | Some current ->
                        [ if current.Actor <> previous.Actor then
                              problem (field ".actor") $"actor changed from {Actor.describe previous.Actor} to {Actor.describe current.Actor}"
                          if current.At <> previous.At then
                              problem (field ".at") "the time of the first recorded operation changed"
                          for operation in previous.Operations do
                              if not (List.contains operation current.Operations) then
                                  problem (field ".operations") $"operation '{operation}' was removed"
                          for item in previous.Evidence do
                              if not (List.contains item current.Evidence) then
                                  problem (field ".evidence") $"evidence '{item}' was removed"
                          match previous.Reason with
                          | Some reason when current.Reason <> Some reason -> problem (field ".reason") "reason was rewritten"
                          | _ -> () ])

            let originProblems =
                match originator before, originator after with
                | Some previous, Some current when previous.Key <> current.Key ->
                    [ problem "contributions" $"originator changed from {previous.Key} to {current.Key}" ]
                | _ -> []

            let lineageProblems =
                [ for reference in before.DerivedFrom do
                      if not (List.contains reference after.DerivedFrom) then
                          problem "derivedFrom" $"lineage reference '{reference}' was removed"
                  for reference, _ in before.Sources do
                      if not (after.Sources |> List.exists (fun (key, _) -> key = reference)) then
                          problem $"sources.{reference}" "lineage snapshot was removed"
                  if before.Subject.IsSome && after.Subject <> before.Subject then
                      problem "subject" "subject changed; a different subject needs its own record that derives from this one"
                  if after.Version.Major <> before.Version.Major then
                      problem "version" "major version changed in place"
                  elif (after.Version.Minor, after.Version.Patch) < (before.Version.Minor, before.Version.Patch) then
                      problem "version" "a record must not be relabelled as an older version" ]

            contributionProblems @ originProblems @ lineageProblems

    // ----------------------------------------------------------------- codec

    let private stringOf (node: JsonNode) =
        match node with
        | :? JsonValue as value ->
            match value.TryGetValue<string>() with
            | true, text -> Some text
            | _ -> None
        | _ -> None

    let private collect (results: Result<'value, Problem list> list) : Result<'value list, Problem list> =
        match results |> List.collect (function Error found -> found | Ok _ -> []) with
        | [] -> results |> List.choose (function Ok value -> Some value | Error _ -> None) |> Ok
        | found -> Error found

    let private errorsOf (results: Result<unit, Problem list> list) =
        results |> List.collect (function Error found -> found | Ok () -> [])

    let private stringArray (field: string) (node: JsonNode) : Result<string list, Problem list> =
        match node with
        | null -> Ok []
        | :? JsonArray as items ->
            let values = items |> Seq.map stringOf |> Seq.toList

            if values |> List.forall Option.isSome then
                Ok(List.choose id values)
            else
                Error [ problem field "must be an array of strings" ]
        | _ -> Error [ problem field "must be an array of strings" ]

    let private parseActor (field: string) (node: JsonNode) : Result<Actor, Problem list> =
        match node with
        | :? JsonObject as item ->
            let text (name: string) = stringOf item[name]

            match text "kind" with
            | None -> Error [ problem $"{field}.kind" "actor kind is required" ]
            | Some kindText ->
                match ActorKind.tryParse kindText with
                | None -> Error [ problem $"{field}.kind" $"unknown actor kind '{kindText}'" ]
                | Some kind ->
                    Ok
                        { Kind = kind
                          Id = text "id" |> Option.defaultValue ""
                          Provider = text "provider"
                          Model = text "model"
                          Runtime = text "runtime" }
        | null -> Error [ problem field "actor is required" ]
        | _ -> Error [ problem field "actor must be an object" ]

    let private parseContribution (key: string) (node: JsonNode) : Result<Contribution, Problem list> =
        let prefix = $"contributions.{key}"

        match node with
        | :? JsonObject as entry ->
            let operations = stringArray $"{prefix}.operations" entry["operations"]
            let evidence = stringArray $"{prefix}.evidence" entry["evidence"]
            let actor = parseActor $"{prefix}.actor" entry["actor"]

            match operations, evidence, actor with
            | Ok operations, Ok evidence, Ok actor ->
                Ok
                    { Key = key
                      Operations = operations
                      At = stringOf entry["at"] |> Option.defaultValue ""
                      Last = stringOf entry["last"]
                      Actor = actor
                      Reason = stringOf entry["reason"]
                      Evidence = evidence }
            | _ ->
                Error(
                    errorsOf [ Result.map ignore operations; Result.map ignore evidence; Result.map ignore actor ]
                )
        | _ -> Error [ problem prefix "a contribution must be an object" ]

    let rec private readAt (depth: int) (node: JsonNode) : Result<Reading, Problem list> =
        match node with
        | :? JsonObject as raw ->
            let body (version: ContractVersion) : Result<Record, Problem list> =
                let contributions =
                    match raw["contributions"] with
                    | :? JsonObject as entries ->
                        entries |> Seq.map (fun pair -> parseContribution pair.Key pair.Value) |> Seq.toList |> collect
                    | null -> Error [ problem "contributions" "contributions is required" ]
                    | _ -> Error [ problem "contributions" "contributions must be an object keyed by EXE-... or CTB-..." ]

                let derivedFrom = stringArray "derivedFrom" raw["derivedFrom"]

                let subject =
                    match raw["subject"] with
                    | null -> Ok None
                    | value ->
                        match stringOf value with
                        | Some text -> Ok(Some text)
                        | None -> Error [ problem "subject" "subject must be a string" ]

                let sources =
                    match raw["sources"] with
                    | null -> Ok []
                    | :? JsonObject as snapshots when depth >= Record.MaxSourceDepth && snapshots.Count > 0 ->
                        Error [ problem "sources" $"lineage snapshots nest deeper than {Record.MaxSourceDepth} levels" ]
                    | :? JsonObject as snapshots ->
                        snapshots
                        |> Seq.map (fun pair ->
                            match readAt (depth + 1) pair.Value with
                            | Ok(Reading.Current source)
                            | Ok(Reading.Unversioned source) -> Ok(pair.Key, Snapshot.Known source)
                            | Ok(Reading.Unsupported version) -> Ok(pair.Key, Snapshot.Opaque version)
                            | Error found ->
                                Error(found |> List.map (fun item -> { item with Field = $"sources.{pair.Key}.{item.Field}" })))
                        |> Seq.toList
                        |> collect
                    | _ -> Error [ problem "sources" "sources must be an object keyed by lineage reference" ]

                match contributions, derivedFrom, subject, sources with
                | Ok contributions, Ok derivedFrom, Ok subject, Ok sources ->
                    Ok
                        { Version = version
                          Subject = subject
                          Contributions = contributions
                          DerivedFrom = derivedFrom
                          Sources = sources }
                | _ ->
                    Error(
                        errorsOf
                            [ Result.map ignore contributions
                              Result.map ignore derivedFrom
                              Result.map ignore subject
                              Result.map ignore sources ]
                    )

            match raw["contract"], raw["version"] with
            | null, null -> body ContractVersion.current |> Result.map Reading.Unversioned
            | contract, _ when stringOf contract <> Some Record.ContractName ->
                Error [ problem "contract" $"contract must be '{Record.ContractName}'" ]
            | _, version ->
                match version |> stringOf |> Option.bind ContractVersion.tryParse with
                | None -> Error [ problem "version" "version must be a semantic version (MAJOR.MINOR.PATCH)" ]
                | Some parsed when not (ContractVersion.isSupported parsed) -> Ok(Reading.Unsupported(ContractVersion.code parsed))
                | Some parsed -> body parsed |> Result.map Reading.Current
        | _ -> Error [ problem "" "a provenance record must be a JSON object" ]

    let private validate (node: JsonNode) : Result<Reading, Problem list> =
        match readAt 0 node with
        | Ok(Reading.Current record as reading)
        | Ok(Reading.Unversioned record as reading) ->
            match Record.problems record with
            | [] -> Ok reading
            | found -> Error found
        | other -> other

    /// A provenance record as carried: its verbatim JSON text plus how it
    /// read. Only a well-formed record, or one in an unsupported major, can
    /// become a Document, so malformed provenance is rejected at the edge
    /// rather than silently dropped. Requirement: AEG-PROV-003.
    type Document =
        private
            { Raw: string
              Parsed: Reading }

        /// The record exactly as carried (compact JSON, every field kept).
        member this.Text = this.Raw

        member this.Reading = this.Parsed

    [<RequireQualifiedAccess>]
    module Document =
        let private ofNode (node: JsonNode) : Result<Document, Problem list> =
            validate node |> Result.map (fun reading -> { Raw = node.ToJsonString(); Parsed = reading })

        /// Read and validate a record. An unsupported major is accepted, to be
        /// carried verbatim; anything malformed is an error.
        let parse (text: string) : Result<Document, Problem list> =
            try
                match JsonNode.Parse text with
                | null -> Error [ problem "" "a provenance record must be a JSON object" ]
                | node -> ofNode node
            with :? JsonException as error ->
                Error [ problem "" $"not valid JSON: {error.Message}" ]

        let text (document: Document) = document.Text

        let reading (document: Document) = document.Reading

        /// The interpreted record, or None for an unsupported major.
        let record (document: Document) =
            match document.Reading with
            | Reading.Current record
            | Reading.Unversioned record -> Some record
            | Reading.Unsupported _ -> None

        /// The namespaced reference of an Aegis fault, e.g. `aegis:fault/F-17`.
        let subjectOf (faultId: FaultId) = $"aegis:fault/{faultId.Value}"

        let private node (document: Document) = JsonNode.Parse document.Text

        let private sameNode (left: JsonNode) (right: JsonNode) = JsonNode.DeepEquals(left, right)

        /// JSON-level preservation: everything `before` carried, including
        /// fields this codec does not model on the record, each contribution
        /// and each actor, is present and unchanged in `after`, except the
        /// fields a contribution may legitimately extend.
        let private preservationProblems (before: JsonObject) (after: JsonObject) : Problem list =
            let envelope = set [ "contributions"; "derivedFrom"; "sources"; "version"; "contract" ]
            let extendable = set [ "operations"; "evidence"; "last"; "reason" ]

            let topLevel =
                before
                |> Seq.filter (fun pair -> not (envelope.Contains pair.Key))
                |> Seq.filter (fun pair -> not (after.ContainsKey pair.Key) || not (sameNode pair.Value after[pair.Key]))
                |> Seq.map (fun pair -> problem pair.Key "field was removed or changed; fields a consumer does not model must be preserved")
                |> Seq.toList

            let contributions =
                match before["contributions"], after["contributions"] with
                | (:? JsonObject as previous), (:? JsonObject as current) ->
                    previous
                    |> Seq.collect (fun pair ->
                        match pair.Value, current[pair.Key] with
                        | (:? JsonObject as entry), (:? JsonObject as successor) ->
                            entry
                            |> Seq.filter (fun field -> not (extendable.Contains field.Key))
                            |> Seq.filter (fun field -> not (successor.ContainsKey field.Key) || not (sameNode field.Value successor[field.Key]))
                            |> Seq.map (fun field ->
                                problem $"contributions.{pair.Key}.{field.Key}" "another contributor's entry must be preserved verbatim")
                            |> Seq.toList
                        | _ -> [])
                    |> Seq.toList
                | _ -> []

            let snapshots =
                match before["sources"], after["sources"] with
                | (:? JsonObject as previous), (:? JsonObject as current) ->
                    previous
                    |> Seq.filter (fun pair -> current.ContainsKey pair.Key && not (sameNode pair.Value current[pair.Key]))
                    |> Seq.map (fun pair -> problem $"sources.{pair.Key}" "lineage snapshot must be carried verbatim")
                    |> Seq.toList
                | _ -> []

            topLevel @ contributions @ snapshots

        /// Whether `after` is a non-destructive successor of `before`
        /// (RQ-ROS-2026-A015). An unsupported major must be carried unchanged.
        let successorProblems (before: Document) (after: Document) : Problem list =
            match before.Reading, after.Reading with
            | Reading.Unsupported _, _ ->
                if sameNode (node before) (node after) then
                    []
                else
                    [ problem "" "a record in an unsupported major version must be carried verbatim" ]
            | _, Reading.Unsupported _ ->
                [ problem "version" "a supported record was replaced by an unsupported major version" ]
            | _ ->
                match record before, record after with
                | Some previous, Some current ->
                    Record.successorProblems previous current
                    @ preservationProblems ((node before).AsObject()) ((node after).AsObject())
                | _ -> [ problem "" "unreachable: both records are interpretable" ]

        /// `successorProblems` over two records as received. A malformed
        /// successor is never a valid one; a malformed predecessor is not
        /// judged at all.
        let successorProblemsOfText (before: string) (after: string) : Problem list =
            match parse before, parse after with
            | Error _, _ -> [ problem "" "the previous record is malformed; refusing to judge a successor of it" ]
            | _, Error found -> found
            | Ok previous, Ok current -> successorProblems previous current

        let private strings (values: string list) =
            JsonArray(values |> List.map (fun value -> JsonValue.Create value :> JsonNode) |> List.toArray)

        let private actorNode (actor: Actor) =
            let result = JsonObject()
            result["kind"] <- JsonValue.Create(ActorKind.code actor.Kind)
            result["id"] <- JsonValue.Create actor.Id

            for name, value in [ "provider", actor.Provider; "model", actor.Model; "runtime", actor.Runtime ] do
                value |> Option.iter (fun (text: string) -> result[name] <- JsonValue.Create text)

            result

        /// The canonical contribution entry: operations, at, last?, actor,
        /// reason?, evidence?.
        let contributionNode (contribution: Contribution) =
            let result = JsonObject()
            result["operations"] <- strings contribution.Operations
            result["at"] <- JsonValue.Create contribution.At
            contribution.Last |> Option.iter (fun last -> result["last"] <- JsonValue.Create last)
            result["actor"] <- actorNode contribution.Actor
            contribution.Reason |> Option.iter (fun reason -> result["reason"] <- JsonValue.Create reason)

            if not contribution.Evidence.IsEmpty then
                result["evidence"] <- strings contribution.Evidence

            result

        // The functions below build a fresh JsonObject from the immutable
        // text, adjust it locally and serialize it again; no node escapes, so
        // the mutation the JSON DOM requires is never observable.

        let private withEnvelope (raw: JsonObject) =
            if isNull raw["contract"] then
                let result = JsonObject()
                result["contract"] <- JsonValue.Create Record.ContractName
                result["version"] <- JsonValue.Create(ContractVersion.code ContractVersion.current)

                for pair in raw do
                    result[pair.Key] <- (if isNull pair.Value then null else pair.Value.DeepClone())

                result
            else
                raw

        /// Append one contribution, or extend the same execution's own entry.
        /// Refuses an unsupported major, malformed provenance, re-attribution,
        /// a second or late `created`; proves the result is a non-destructive
        /// successor before returning it. A legacy unversioned block gains the
        /// envelope. Requirement: AEG-PROV-004.
        let append (contribution: Contribution) (document: Document) : Result<Document, Problem list> =
            match document.Reading with
            | Reading.Unsupported version ->
                Error [ problem "version" $"version {version} is not supported; the record must be carried verbatim, not extended" ]
            | Reading.Current current
            | Reading.Unversioned current ->
                match Contribution.problems contribution with
                | (_ :: _) as found ->
                    Error(found |> List.map (fun (field, message) -> problem $"contributions.{contribution.Key}.{field}" message))
                | [] ->
                    match Record.merge contribution current with
                    | Error message -> Error [ problem $"contributions.{contribution.Key}" message ]
                    | Ok merged ->
                        let result = withEnvelope ((node document).AsObject())
                        let entries = result["contributions"].AsObject()
                        let canonical = contributionNode merged

                        match entries[contribution.Key] with
                        | :? JsonObject as existing ->
                            for name in [ "operations"; "last"; "evidence"; "reason" ] do
                                match canonical[name] with
                                | null -> ()
                                | value -> existing[name] <- value.DeepClone()
                        | _ -> entries[contribution.Key] <- canonical

                        ofNode result
                        |> Result.bind (fun next ->
                            match successorProblems document next with
                            | [] -> Ok next
                            | found -> Error(problem "" "the appended record failed its own preservation check" :: found))

        /// Record one attributed act on the subject.
        let contribute (operation: string) (at: DateTimeOffset) (by: Attribution) (document: Document) =
            match Attribution.problems by with
            | [] -> append (Contribution.ofAttribution operation at by) document
            | found -> Error(found |> List.map (problem "attribution"))

        /// Start the provenance of a finding. The discovering actor is the
        /// single `created` contribution; lineage names the affected artifacts
        /// and each held source record is carried verbatim, never merged into
        /// the finding's own contributors. Requirement: AEG-PROV-003.
        let discovered
            (subject: string)
            (at: DateTimeOffset)
            (by: Attribution)
            (lineage: string list)
            (sources: (string * Document) list)
            : Result<Document, Problem list> =
            match Attribution.problems by with
            | (_ :: _) as found -> Error(found |> List.map (problem "attribution"))
            | [] ->
                let references = lineage @ (sources |> List.map fst) |> List.distinct
                let result = JsonObject()
                result["contract"] <- JsonValue.Create Record.ContractName
                result["version"] <- JsonValue.Create(ContractVersion.code ContractVersion.current)
                result["subject"] <- JsonValue.Create subject
                let entries = JsonObject()
                let creator = Contribution.ofAttribution Operation.Created at by
                entries[creator.Key] <- contributionNode creator
                result["contributions"] <- entries

                if not references.IsEmpty then
                    result["derivedFrom"] <- strings references

                match sources |> List.distinctBy fst with
                | [] -> ()
                | held ->
                    let snapshots = JsonObject()
                    held |> List.iter (fun (reference, source) -> snapshots[reference] <- node source)
                    result["sources"] <- snapshots

                ofNode result

        /// The contributions an Aegis lifecycle event makes, as
        /// (operation, time, attribution). `by` performed the event;
        /// `validatedBy` verified a resolution or a recovery.
        ///
        /// FaultAcknowledged -> x-handled; RecoveryConcluded (Succeeded or
        /// AwaitingVerification) -> x-remediated; FaultResolved -> x-resolved,
        /// or x-dismissed when it no longer applies; a verified resolution or
        /// succeeded recovery with `validatedBy` -> x-validated;
        /// FaultEscalated -> modified; FaultReopened -> x-reopened;
        /// FaultSuperseded -> superseded. Recording, repetition, suppression
        /// and containment add no contribution: discovery is `discovered`.
        /// Requirement: AEG-PROV-004.
        let contributionsFor
            (by: Attribution option)
            (validatedBy: Attribution option)
            (ev: AegisEvent)
            : Result<(string * DateTimeOffset * Attribution) list, Problem list> =
            let performed operation at =
                by |> Option.map (fun attribution -> operation, at, attribution) |> Option.toList

            let validation verified at =
                match validatedBy, verified with
                | None, _ -> Ok []
                | Some attribution, true -> Ok [ Operation.Validated, at, attribution ]
                | Some _, false ->
                    Error [ problem "validatedBy" "a validating actor needs a verified resolution or a succeeded recovery" ]

            let only operations =
                match validatedBy with
                | Some _ -> Error [ problem "validatedBy" "only a resolution or a concluded recovery can be validated" ]
                | None -> Ok operations

            match ev with
            | FaultAcknowledged(_, _, at) -> only (performed Operation.Handled at)
            | RecoveryConcluded(_, _, outcome, at) ->
                let remediated =
                    match outcome with
                    | Succeeded
                    | AwaitingVerification -> performed Operation.Remediated at
                    | FailedWith _ -> []

                validation (outcome = Succeeded) at |> Result.map (fun validated -> remediated @ validated)
            | FaultResolved(_, resolution) ->
                let operation =
                    match resolution.Kind with
                    | NoLongerApplies -> Operation.Dismissed
                    | ResolvedAutomatically
                    | ResolvedManually -> Operation.Resolved

                validation resolution.Verified resolution.Timestamp
                |> Result.map (fun validated -> performed operation resolution.Timestamp @ validated)
            | FaultEscalated(_, _, _, at) -> only (performed Operation.Modified at)
            | FaultReopened(_, at, _) -> only (performed Operation.Reopened at)
            | FaultSuperseded(_, _, at) -> only (performed Operation.Superseded at)
            | FaultRecorded _
            | FaultSuppressed _
            | FaultRepeated _
            | RecoveryStarted _
            | ItemQuarantined _
            | ItemReleased _
            | ItemDeadLettered _
            | SinkFailed _ -> only []

        /// Apply an Aegis lifecycle event to a fault's provenance record:
        /// the successor carries every earlier contributor unchanged plus the
        /// acts this event attributes. Refuses an event about another fault.
        /// Requirement: AEG-PROV-004.
        let advance (by: Attribution option) (validatedBy: Attribution option) (ev: AegisEvent) (document: Document) =
            let subjectProblems =
                match record document |> Option.bind _.Subject, ev.FaultId with
                | Some subject, Some faultId when subject <> subjectOf faultId ->
                    [ problem "subject" $"the event concerns {subjectOf faultId}, not {subject}" ]
                | _ -> []

            match subjectProblems with
            | (_ :: _) as found -> Error found
            | [] ->
                contributionsFor by validatedBy ev
                |> Result.bind (
                    List.fold
                        (fun state (operation, at, attribution) -> state |> Result.bind (contribute operation at attribution))
                        (Ok document)
                )
