module Aegis.Tests.Provenance

// Attribution and fault provenance: who discovered, remediated and validated
// a fault, in which run. Requirements: AEG-PROV-001..006; additional 38.

open System
open System.Text.Json.Nodes
open Xunit
open Aegis
open Aegis.Provenance

let private at = DateTimeOffset(2026, 9, 26, 12, 0, 0, TimeSpan.Zero)
let private later (minutes: int) = at.AddMinutes(float minutes)

let private fault =
    { Id = FaultId "F-17"
      CorrelationId = CorrelationId "CORR17"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = None
      Operation = "Chrona.Auth.Validate"
      Category = SecurityFailure
      Code = FaultCode "CHRONA.AUTH.TOKEN_ACCEPTED_EXPIRED"
      Severity = FaultSeverity.Error
      Impact = OperationOnly
      Domain = LocalOperation
      Radius = OneOperation
      Retention = AuditRequired
      Persistence = Persistent
      Owner = None
      Dependencies = []
      UserMessage = "Sign-in failed."
      TechnicalDetails = None
      Context = Map.empty
      Recovery = NoRecovery
      Diagnostics =
        { noDiagnostics with
            Environment = Some { unknownEnvironment with CommitSha = Some "abc123" } }
      Cause = None }

let private ok result =
    match result with
    | Ok value -> value
    | Error problems -> failwith $"%A{problems}"

let private gemini = Actor.agent "google/gemini-cli" "google" "gemini-2.5-pro" "gemini-cli"
let private discoverer = Attribution.create gemini "EXE-20260926T120000000Z-d4d4d4d4" |> ok
let private remediator = Attribution.create (Actor.agent "anthropic/claude-code" "anthropic" "unknown" "claude-code") "EXE-aegis.run-7" |> ok
let private kevin = Attribution.create (Actor.human "kevin") "CTB-20260926-review" |> ok

let private finding () =
    Document.discovered (Document.subjectOf fault.Id) at discoverer [ "git:commit/abc123" ] [] |> ok

let private env (pairs: (string * string) list) =
    let values = Map.ofList pairs
    fun key -> Map.tryFind key values

// ------------------------------------------------------------ identity

[<Fact>]
let ``a declared agent is read from the whitelisted environment`` () =
    let actor =
        Actor.fromEnvironment (
            env
                [ "ROS_ACTOR_KIND", "agent"
                  "ROS_TELEMETRY_PROVIDER", "anthropic"
                  "ROS_TELEMETRY_RUNTIME", "claude-code" ]
        )
        |> ok

    Assert.Equal(Actor.agent "anthropic/claude-code" "anthropic" "unknown" "claude-code", actor)

[<Fact>]
let ``nothing declared resolves to unknown rather than a guess`` () =
    Assert.Equal(Actor.unknown, Actor.fromEnvironment (env []) |> ok)

[<Fact>]
let ``GitHub Actions with nothing declared resolves to automation`` () =
    let actor = Actor.fromEnvironment (env [ "GITHUB_ACTIONS", "true" ]) |> ok
    Assert.Equal(ActorKind.Automation, actor.Kind)
    Assert.Equal("github/github-actions", actor.Id)

[<Fact>]
let ``a declared human carries no provider, model or runtime`` () =
    let actor = Actor.fromEnvironment (env [ "ROS_ACTOR_KIND", "human"; "ROS_ACTOR", "kevin" ]) |> ok
    Assert.Equal(Actor.human "kevin", actor)

[<Fact>]
let ``an actor kind outside the vocabulary, or a credential, is refused`` () =
    Assert.True((Actor.fromEnvironment (env [ "ROS_ACTOR_KIND", "robot" ])).IsError)
    Assert.True((Actor.fromEnvironment (env [ "ROS_ACTOR", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" ])).IsError)

[<Fact>]
let ``a propagated Praxis execution is used, otherwise Aegis keys its own run`` () =
    Assert.Equal(Ok "EXE-20260926T120000000Z-d4d4d4d4", Execution.fromEnvironment (env [ "ROS_EXECUTION_ID", "EXE-20260926T120000000Z-d4d4d4d4" ]) "run-1")
    Assert.Equal(Ok "EXE-aegis.run-1", Execution.fromEnvironment (env []) "run-1")
    Assert.True((Execution.fromEnvironment (env [ "ROS_EXECUTION_ID", "not-an-execution" ]) "run-1").IsError)
    Assert.True((Execution.ofRun "bad run").IsError)
    Assert.Equal(Ok "CTB-20260926-review", Execution.outsideRun "20260926-review")

[<Fact>]
let ``an agent must be keyed by an execution`` () =
    Assert.True((Attribution.create gemini "CTB-20260926-x").IsError)

[<Fact>]
let ``an agent must state provider, model and runtime`` () =
    let incomplete = { gemini with Model = None }
    Assert.True((Attribution.create incomplete "EXE-aegis.run-1").IsError)

// -------------------------------------------------------- serialization

let private allEvents =
    [ FaultRecorded fault
      FaultSuppressed(fault, "throttled")
      FaultRepeated(fault.Id, later 1)
      FaultAcknowledged(fault.Id, Operator, later 2)
      RecoveryStarted(
          fault.Id,
          { Action = Reload
            AttemptNumber = 1
            Actor = Agent
            Timestamp = later 3
            CorrelationId = fault.CorrelationId
            Outcome = AwaitingVerification }
      )
      RecoveryConcluded(fault.Id, 1, Succeeded, later 4)
      FaultEscalated(fault.Id, FaultSeverity.Error, FaultSeverity.Critical, later 5)
      FaultResolved(fault.Id, { Timestamp = later 6; Kind = ResolvedManually; Action = None; Verified = true })
      FaultReopened(fault.Id, later 7, "recurred")
      FaultSuperseded(fault.Id, FaultId "F-18", later 8)
      SinkFailed("github", FaultCode "AEGIS.SINK.WRITE_FAILED", "unreachable") ]

[<Fact>]
let ``without provenance every event and fault is byte-identical to the v1 payload`` () =
    for ev in allEvents do
        Assert.Equal(Ok(Serialization.event Redaction.defaultRules (EventId "01E1") ev), Serialization.eventWith Redaction.defaultRules Serialization.noOptions (EventId "01E1") ev)

    Assert.Equal(Ok(Serialization.fault Redaction.defaultRules fault), Serialization.faultWith Redaction.defaultRules Serialization.noOptions fault)

[<Fact>]
let ``every lifecycle event can carry an attribution without changing its v1 members`` () =
    let options = { Serialization.noOptions with Attribution = Some remediator }

    for ev in allEvents do
        let plain = Serialization.event Redaction.defaultRules (EventId "01E1") ev
        let attributed = Serialization.eventWith Redaction.defaultRules options (EventId "01E1") ev |> ok
        Assert.StartsWith(plain.Substring(0, plain.Length - 1) + ",\"attribution\":", attributed)

        match Store.index attributed, Store.index plain with
        | Ok withIt, Ok withoutIt -> Assert.Equal(withoutIt, withIt)
        | other -> failwith $"%A{other}"

[<Fact>]
let ``an agent attribution is written in contract key order`` () =
    let options = { Serialization.noOptions with Attribution = Some discoverer }
    let payload = Serialization.eventWith Redaction.defaultRules options (EventId "01E1") (FaultRecorded fault) |> ok

    Assert.EndsWith(
        ",\"attribution\":{\"execution\":\"EXE-20260926T120000000Z-d4d4d4d4\",\"actor\":{\"kind\":\"agent\",\"id\":\"google/gemini-cli\",\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"runtime\":\"gemini-cli\"}}}",
        payload
    )

[<Fact>]
let ``a human is not identified unless that is necessary`` () =
    let write attribution =
        Serialization.eventWith Redaction.defaultRules { Serialization.noOptions with Attribution = Some attribution } (EventId "01E1") (FaultAcknowledged(fault.Id, Operator, at))
        |> ok

    let withheld = write kevin
    Assert.EndsWith(",\"attribution\":{\"execution\":\"CTB-20260926-review\",\"actor\":{\"kind\":\"human\",\"id\":\"[redacted]\"}}}", withheld)
    Assert.DoesNotContain("kevin", withheld)
    Assert.DoesNotContain("provider", withheld)

    let identified = write (Attribution.identified kevin)
    Assert.EndsWith("\"actor\":{\"kind\":\"human\",\"id\":\"kevin\"}}}", identified)

[<Fact>]
let ``secrets are refused and never serialized`` () =
    let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    let leaky = { remediator with Reason = Some $"used {token}" }
    let options = { Serialization.noOptions with Attribution = Some leaky }

    Assert.True((Serialization.eventWith Redaction.defaultRules options (EventId "01E1") (FaultRecorded fault)).IsError)
    Assert.True((Attribution.create (Actor.agent "a" "p" token "r") "EXE-aegis.run-1").IsError)
    Assert.True((Document.contribute Operation.Remediated (later 1) leaky (finding ())).IsError)

    // Nor through the reporting path: nothing reaches a sink.
    let collector = Sinks.Collector(capacity = 10)
    let config = { Aegis.configure "Chrona" None [ collector.Sink() ] with Persistence = Blocking }
    Assert.True((Aegis.reportWith config options (FaultRecorded fault)).IsError)
    Assert.Empty collector.Events

[<Fact>]
let ``an attributed event is delivered through the sinks and reads back`` () =
    let collector = Sinks.Collector(capacity = 10)
    let config = Aegis.configure "Chrona" None [ collector.Sink() ]
    let options = { Serialization.noOptions with Attribution = Some remediator }
    let report = Aegis.reportWith config options (RecoveryConcluded(fault.Id, 1, Succeeded, later 4)) |> ok

    Assert.False report.FallbackUsed
    let payload = List.exactlyOne collector.Events
    Assert.Equal(Ok [ "attribution", remediator ], Store.attributions payload)

[<Fact>]
let ``a validating actor is written separately from the performer`` () =
    let ci = Attribution.create Actor.githubActions "EXE-aegis.gh-run-9" |> ok
    let resolved = FaultResolved(fault.Id, { Timestamp = later 6; Kind = ResolvedManually; Action = None; Verified = true })

    let options =
        { Serialization.noOptions with
            Attribution = Some remediator
            ValidatedBy = Some ci }

    let payload = Serialization.eventWith Redaction.defaultRules options (EventId "01E1") resolved |> ok
    Assert.Equal(Ok [ "attribution", remediator; "validatedBy", ci ], Store.attributions payload)

    let unverified = FaultResolved(fault.Id, { Timestamp = later 6; Kind = ResolvedManually; Action = None; Verified = false })
    Assert.True((Serialization.eventWith Redaction.defaultRules options (EventId "01E1") unverified).IsError)

[<Fact>]
let ``the index tolerates events with and without provenance`` () =
    let options =
        { Serialization.noOptions with
            Attribution = Some discoverer
            Provenance = Some(finding ()) }

    let payload = Serialization.eventWith Redaction.defaultRules options (EventId "01E1") (FaultRecorded fault) |> ok
    Assert.True((Store.index payload).IsOk)
    Assert.Equal(Ok [], Store.attributions (Serialization.event Redaction.defaultRules (EventId "01E1") (FaultRecorded fault)))
    Assert.Equal(Ok None, Store.provenance (Serialization.event Redaction.defaultRules (EventId "01E1") (FaultRecorded fault)))
    Assert.Equal(Ok(Some(finding ())), Store.provenance payload)

[<Fact>]
let ``a stored event with malformed provenance is reported, not dropped`` () =
    let payload = """{"schema":"aegis/event/v1","eventId":"01E1","eventType":"FaultRecorded","provenance":{"contract":"praxis.provenance-record","version":"1.0.0"}}"""

    match Store.provenance payload with
    | Error(Store.Malformed _) -> ()
    | other -> failwith $"%A{other}"

    let badActor = """{"schema":"aegis/event/v1","eventId":"01E1","eventType":"FaultRecorded","attribution":{"execution":"CTB-x","actor":{"kind":"agent","id":"a"}}}"""

    match Store.attributions badActor with
    | Error(Store.Malformed _) -> ()
    | other -> failwith $"%A{other}"

[<Fact>]
let ``a fault's provenance record must describe that fault`` () =
    let other = { fault with Id = FaultId "F-99" }
    let options = { Serialization.noOptions with Provenance = Some(finding ()) }
    Assert.True((Serialization.faultWith Redaction.defaultRules options other).IsError)
    Assert.True((Serialization.faultWith Redaction.defaultRules options fault).IsOk)
    let sinkFailed = SinkFailed("github", FaultCode "AEGIS.SINK.WRITE_FAILED", "unreachable")
    Assert.True((Serialization.eventWith Redaction.defaultRules options (EventId "01E1") sinkFailed).IsError)

// ---------------------------------------------------- provenance record

[<Fact>]
let ``the discoverer is the single created contribution and lineage names the affected artifact`` () =
    let record = Document.record (finding ()) |> Option.get
    Assert.Equal(Some "aegis:fault/F-17", record.Subject)
    Assert.Equal<string list>([ "git:commit/abc123" ], record.DerivedFrom)

    match record.Contributions with
    | [ creation ] ->
        Assert.Equal("EXE-20260926T120000000Z-d4d4d4d4", creation.Key)
        Assert.Equal<string list>([ Operation.Created ], creation.Operations)
        Assert.Equal(gemini, creation.Actor)
    | other -> failwith $"%A{other}"

[<Fact>]
let ``lifecycle operations append contributors without displacing the discoverer`` () =
    let apply ev by validatedBy document = document |> Result.bind (Document.advance by validatedBy ev)

    let result =
        Ok(finding ())
        |> apply (FaultAcknowledged(fault.Id, Operator, later 1)) (Some kevin) None
        |> apply (FaultEscalated(fault.Id, FaultSeverity.Error, FaultSeverity.Critical, later 2)) (Some kevin) None
        |> apply (RecoveryConcluded(fault.Id, 1, Succeeded, later 3)) (Some remediator) None
        |> apply (FaultReopened(fault.Id, later 4, "recurred")) (Some remediator) None
        |> apply (FaultSuperseded(fault.Id, FaultId "F-18", later 5)) (Some kevin) None
        |> ok

    let record = Document.record result |> Option.get
    Assert.Equal(Some "EXE-20260926T120000000Z-d4d4d4d4", Record.originator record |> Option.map _.Key)

    let byKey = record.Contributions |> List.map (fun c -> c.Key, (c.Operations, c.Last)) |> Map.ofList
    Assert.Equal(([ "x-handled"; "modified"; "superseded" ], Some "2026-09-26T12:05:00.000Z"), byKey["CTB-20260926-review"])
    Assert.Equal(([ "x-remediated"; "x-reopened" ], Some "2026-09-26T12:04:00.000Z"), byKey["EXE-aegis.run-7"])
    Assert.Empty(Document.successorProblems (finding ()) result)

[<Fact>]
let ``a failed recovery remediates nothing, and dismissal is distinct from resolution`` () =
    Assert.Equal(Ok [], Document.contributionsFor (Some remediator) None (RecoveryConcluded(fault.Id, 1, FailedWith "no", later 1)))

    let dismissed = FaultResolved(fault.Id, { Timestamp = later 2; Kind = NoLongerApplies; Action = None; Verified = false })

    match Document.contributionsFor (Some kevin) None dismissed with
    | Ok [ operation, _, _ ] -> Assert.Equal(Operation.Dismissed, operation)
    | other -> failwith $"%A{other}"

[<Fact>]
let ``re-attributing an execution to another actor is refused`` () =
    let impostor = { remediator with Actor = Actor.agent "openai/codex" "openai" "unknown" "codex" }

    let result =
        finding ()
        |> Document.contribute Operation.Remediated (later 1) remediator
        |> Result.bind (Document.contribute Operation.Validated (later 2) impostor)

    Assert.True result.IsError

[<Fact>]
let ``a second creation, or a contribution before the creation, is refused`` () =
    Assert.True((Document.contribute Operation.Created (later 1) remediator (finding ())).IsError)
    Assert.True((Document.contribute Operation.Remediated (at.AddMinutes -1.0) remediator (finding ())).IsError)

[<Fact>]
let ``an event about another fault cannot advance this fault's record`` () =
    Assert.True((Document.advance (Some remediator) None (RecoveryConcluded(FaultId "F-99", 1, Succeeded, later 1)) (finding ())).IsError)

[<Fact>]
let ``unknown fields survive an Aegis append`` () =
    let text =
        """{"contract":"praxis.provenance-record","version":"1.2.0","subject":"aegis:fault/F-17","x-envelope":{"a":1},
            "contributions":{"EXE-20260926T120000000Z-d4d4d4d4":{"operations":["created"],"at":"2026-09-26T12:00:00.000Z",
            "actor":{"kind":"agent","id":"google/gemini-cli","provider":"google","model":"unknown","runtime":"gemini-cli","x-team":"sec"},
            "attestation":{"type":"x-future"}}}}"""

    let document = Document.parse text |> ok
    let appended = Document.contribute Operation.Remediated (later 1) remediator document |> ok
    let json = JsonNode.Parse appended.Text
    let value (path: string list) = path |> List.fold (fun (node: JsonNode) (name: string) -> node[name]) json
    Assert.Equal("1.2.0", value [ "version" ] |> string)
    Assert.Equal("1", value [ "x-envelope"; "a" ] |> string)
    Assert.Equal("sec", value [ "contributions"; "EXE-20260926T120000000Z-d4d4d4d4"; "actor"; "x-team" ] |> string)
    Assert.Equal("x-future", value [ "contributions"; "EXE-20260926T120000000Z-d4d4d4d4"; "attestation"; "type" ] |> string)

[<Fact>]
let ``an unsupported major is carried verbatim and never extended`` () =
    let text = """{"contract":"praxis.provenance-record","version":"2.0.0","contributions":[{"execution":"x"}],"x-v2":true}"""
    let document = Document.parse text |> ok
    Assert.Equal(Reading.Unsupported "2.0.0", document.Reading)
    Assert.True((Document.contribute Operation.Remediated (later 1) remediator document).IsError)

    let payload =
        Serialization.eventWith Redaction.defaultRules { Serialization.noOptions with Provenance = Some document } (EventId "01E1") (FaultRecorded fault)
        |> ok

    Assert.EndsWith(",\"provenance\":" + JsonNode.Parse(text).ToJsonString() + "}", payload)

[<Fact>]
let ``malformed provenance is rejected`` () =
    Assert.True((Document.parse "{").IsError)
    Assert.True((Document.parse """{"contract":"praxis.provenance-record","version":"1.0"}""").IsError)
    Assert.True((Document.parse """{"contract":"praxis.provenance-record","version":"1.0.0","contributions":{"EXE-x":{"operations":["created"],"at":"2026-09-26T12:00:00.000Z","actor":{"kind":"agent","id":"a"}}}}""").IsError)

[<Fact>]
let ``a legacy unversioned block gains the envelope only when extended`` () =
    let legacy =
        """{"contributions":{"EXE-20260926T120000000Z-d4d4d4d4":{"operations":["created"],"at":"2026-09-26T12:00:00.000Z","actor":{"kind":"agent","id":"google/gemini-cli","provider":"google","model":"unknown","runtime":"gemini-cli"}}}}"""

    let document = Document.parse legacy |> ok
    Assert.Equal(JsonNode.Parse(legacy).ToJsonString(), document.Text)
    let appended = Document.contribute Operation.Remediated (later 1) remediator document |> ok
    Assert.StartsWith("{\"contract\":\"praxis.provenance-record\",\"version\":\"1.0.0\",\"contributions\":", appended.Text)

// --------------------------------------------------------------- Tutela

[<Fact>]
let ``Tutela evidence carries the reporting attribution only when supplied`` () =
    let plain = Tutela.tryProjectFault "1.0.0" fault |> Result.defaultWith (fun e -> failwith $"%A{e}")

    match Tutela.tryProjectFaultAttributed "1.0.0" None fault with
    | Ok projected ->
        Assert.Equal(plain, projected.Evidence)
        Assert.True projected.ReportedBy.IsNone
    | Error e -> failwith $"%A{e}"

    match Tutela.tryProjectFaultAttributed "1.0.0" (Some kevin) fault with
    | Ok projected ->
        Assert.Equal(Some Redaction.Placeholder, projected.ReportedBy |> Option.map _.Actor.Id)
        Assert.Equal(plain.Id, projected.Evidence.Id)
        Assert.Equal(plain.Result, projected.Evidence.Result)
    | Error e -> failwith $"%A{e}"

    Assert.True((Tutela.tryProjectFaultAttributed "1.0.0" (Some { remediator with Execution = "nope" }) fault).IsError)

[<Fact>]
let ``a lineage snapshot rewritten into another valid record is still judged destructive`` () =
    let source = finding ()

    let derived =
        Document.discovered "aegis:fault/F-18" (later 10) remediator [] [ "aegis:fault/F-17", source ] |> ok

    let rewritten =
        derived.Text.Replace("\"git:commit/abc123\"", "\"git:commit/other\"") |> Document.parse |> ok

    Assert.NotEmpty(Document.successorProblems derived rewritten)
    // The source's contributors stay lineage: never the derivative's own.
    Assert.Equal<string list>([ "EXE-aegis.run-7" ], (Document.record derived |> Option.get).Contributions |> List.map _.Key)
