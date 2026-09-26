module Aegis.Tests.ProvenanceTests

// Contribution provenance on faults and security findings.
// Requirements: AEG-PROV-001..AEG-PROV-012 (requirements/PROVENANCE-INTEGRATION.md);
// decision DF-AEGIS-2026-DC5B; Praxis DF-ROS-2026-A037, RQ-ROS-2026-A013..A019.

open System
open System.IO
open System.Security.Cryptography
open System.Text.Json.Nodes
open Xunit
open Aegis

// ------------------------------------------------------------------ fixtures

let rec private repositoryRoot (directory: DirectoryInfo) =
    if File.Exists(Path.Combine(directory.FullName, "Aegis.sln")) then directory.FullName
    elif isNull directory.Parent then failwith "could not locate the repository root"
    else repositoryRoot directory.Parent

let private fixtureDirectory =
    Path.Combine(repositoryRoot (DirectoryInfo(Directory.GetCurrentDirectory())), "tests", "fixtures", "praxis-provenance")

let private fixture name = JsonNode.Parse(File.ReadAllText(Path.Combine(fixtureDirectory, name)))

let private name (item: JsonNode) = item["name"].GetValue<string>()

let private at = DateTimeOffset(2026, 9, 26, 9, 0, 0, TimeSpan.Zero)

let private codex = ProvenanceIdentity.agent "openai/codex" "openai" "gpt-5-codex" "codex"
let private claude = ProvenanceIdentity.agent "anthropic/claude-code" "anthropic" "unknown" "claude-code"
let private gemini = ProvenanceIdentity.agent "google/gemini-cli" "google" "unknown" "gemini-cli"
let private ci = ProvenanceIdentity.automation "github/github-actions" "github" "github-actions"
let private kevin = ProvenanceIdentity.human "kevin"

let private exeA1 = "EXE-20260926T090000000Z-a1a1a1a1"
let private exeA2 = "EXE-20260926T100000000Z-a2a2a2a2"
let private exeB1 = "EXE-20260926T093000000Z-b1b1b1b1"
let private ciRun = "EXT-github-actions.run-777-1"

let private finding =
    { Id = FaultId "SF-0001"
      CorrelationId = CorrelationId "CORR-SF"
      Timestamp = at
      Application = "Chrona"
      ApplicationVersion = Some "1.4.2"
      Operation = "Chrona.Query.Build"
      Category = SecurityFailure
      Code = FaultCode "CHRONA.SECURITY.INJECTION_RISK"
      Severity = FaultSeverity.Critical
      Impact = ApplicationUnsafe
      Domain = ApplicationDomain
      Radius = EntireApplication
      Retention = AuditRequired
      Persistence = Persistent
      Owner = Some "QueryBuilder"
      Dependencies = [ "Chrona" ]
      UserMessage = "An unsafe query was blocked."
      TechnicalDetails = Some "unparameterized input reached the query builder"
      Context = Map [ "api_token", Secret "never-in-provenance" ]
      Recovery = ManualIntervention
      Diagnostics =
        { Breadcrumbs = [ { At = at.AddSeconds -5.0; Category = "query"; Message = "built query"; Data = Map.empty } ]
          Environment = Some { unknownEnvironment with CommitSha = Some "5e1f0c2" }
          Snapshot =
            Some
                { Location = "https://example.invalid/snapshots/1"
                  Digest = "sha256:abcdef"
                  Summary = "query builder state"
                  CapturedAt = at } }
      Cause = None }

let private ok result =
    match result with
    | Ok value -> value
    | Error problem -> failwith $"expected Ok, got {problem}"

let private keys (contributions: RecordedContribution list) = contributions |> List.map (fun c -> c.Key)

let private attempt number actor timestamp =
    { Action = ManualIntervention
      AttemptNumber = number
      Actor = actor
      Timestamp = timestamp
      CorrelationId = CorrelationId "CORR-SF"
      Outcome = AwaitingVerification }

let private discovered = Provenance.discovery exeA1 gemini (Some "Aegis review discovers an injection risk") [] finding |> ok

let private remediation =
    RecoveryStarted(finding.Id, attempt 1 Agent (at.AddHours 1.0))
    |> Provenance.attribute exeA2 codex (Some "Another execution of agent A fixes the defect")
    |> ok

let private validation =
    FaultResolved(finding.Id, { Timestamp = at.AddHours 1.5; Kind = ResolvedManually; Action = Some ManualIntervention; Verified = true })
    |> fun ev ->
        Provenance.build [ { Provenance.contribution ciRun ci (at.AddHours 1.5) [ "validated" ] with Reason = Some "CI re-runs the security check" } ] []
        |> ok
        |> fun block -> Provenance.attach block ev

let private history =
    [ Provenance.attach discovered (FaultRecorded finding); remediation; validation ]

// ---------------------------------------------------------- conformance + SHA

[<Fact>]
let ``vendored Praxis fixtures are unchanged (SHA-256 matches SOURCE.json)`` () =
    // AEG-PROV-011: detects any local edit to the vendored contract.
    let source = fixture "SOURCE.json"
    Assert.Equal("kemiller2002/praxis", source["repository"].GetValue<string>())
    Assert.Equal("b0037183389c8b9392919f58521b9487d1b4d5c6", source["commit"].GetValue<string>())
    let files = source["files"].AsObject()
    Assert.Equal(6, files.Count)

    for pair in files do
        use sha = SHA256.Create()
        let bytes = File.ReadAllBytes(Path.Combine(fixtureDirectory, pair.Key))
        let digest = sha.ComputeHash bytes |> Array.map (fun b -> b.ToString "x2") |> String.concat ""
        Assert.Equal(pair.Value.GetValue<string>(), digest)

[<Fact>]
let ``every vendored conformance case reaches the reference verdict and warning count`` () =
    // AEG-PROV-007, AEG-PROV-011.
    let cases = (fixture "cases.json").["cases"].AsArray()
    Assert.Equal(70, cases.Count)

    let failures =
        [ for item in cases do
              let name = item["name"].GetValue<string>()
              let expected = item["expect"].GetValue<string>(), item["warnings"].GetValue<int>()

              let actual =
                  match Provenance.classify (item["block"].ToJsonString()) with
                  | ProvenanceVerdict.Supported warnings -> "supported", warnings.Length
                  | ProvenanceVerdict.Unsupported _ -> "unsupported", 0
                  | ProvenanceVerdict.Malformed _ -> "malformed", 0

              if actual <> expected then
                  $"{name}: expected {expected}, got {actual}" ]

    Assert.Empty failures

[<Fact>]
let ``receive keeps supported and unsupported blocks and rejects every malformed case`` () =
    // AEG-PROV-007: malformed is rejected at the boundary, never repaired.
    for item in (fixture "cases.json").["cases"].AsArray() do
        let json = item["block"].ToJsonString()

        match item["expect"].GetValue<string>(), Provenance.receive json with
        | "malformed", Error problems -> Assert.NotEmpty problems
        | "malformed", Ok _ -> failwith $"{name item}: malformed block was accepted"
        | "unsupported", Ok block ->
            Assert.False block.IsSupported
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse json, JsonNode.Parse block.Json), "unsupported must be kept verbatim")
        | _, Ok block ->
            Assert.True block.IsSupported
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse json, JsonNode.Parse block.Json), "unknown fields must survive")
        | expected, Error problems -> failwith $"{name item}: expected {expected}, got {problems}"

// ------------------------------------------------------------ roles on a fault

[<Fact>]
let ``the discovering agent and its execution are recorded with evidence by reference`` () =
    // AEG-PROV-002, AEG-PROV-006.
    let origin = Provenance.originator discovered |> Option.get
    Assert.Equal(exeA1, origin.Key)
    Assert.Equal(gemini, origin.Actor)
    Assert.Equal<string list>([ "created"; "discovered" ], origin.Operations)
    Assert.Equal("2026-09-26T09:00:00.000Z", origin.At)

    Assert.Equal<string list>(
        [ "aegis:fault/SF-0001#environment"; "aegis:snapshot/sha256:abcdef"; "aegis:fault/SF-0001#breadcrumbs" ],
        origin.Evidence
    )

    // Evidence is referenced, never copied: no context, snapshot location or detail.
    Assert.DoesNotContain("never-in-provenance", discovered.Json)
    Assert.DoesNotContain("example.invalid", discovered.Json)
    Assert.DoesNotContain("unparameterized", discovered.Json)

[<Fact>]
let ``remediation by another agent execution is a later contribution on the recovery event`` () =
    // AEG-PROV-003, AEG-PROV-004.
    let accumulated = ProvenanceHistory.forFault finding.Id history
    Assert.Empty accumulated.Conflicts
    Assert.Equal<string list>([ exeA2 ], Provenance.withRole "remediated" accumulated.Block |> keys)
    Assert.Equal(exeA1, (Provenance.originator accumulated.Block |> Option.get).Key)
    // RecoveryActor stays a role category; the identity is in the block.
    match remediation.Event with
    | RecoveryStarted(_, recorded) -> Assert.Equal(Agent, recorded.Actor)
    | other -> failwith $"unexpected {other}"

[<Fact>]
let ``validation by CI automation is recorded under its foreign execution key`` () =
    let accumulated = ProvenanceHistory.forFault finding.Id history
    let validators = Provenance.withRole "validated" accumulated.Block
    Assert.Equal<string list>([ ciRun ], keys validators)
    Assert.Equal("automation", validators.Head.Actor.Kind)
    Assert.Equal(Some "github-actions", Provenance.foreignSystem ciRun)

[<Fact>]
let ``a verified resolution by one actor defaults to resolved and validated`` () =
    let ev = FaultResolved(finding.Id, { Timestamp = at.AddHours 2.0; Kind = ResolvedManually; Action = None; Verified = true })
    Assert.Equal<string list>([ "resolved"; "validated" ], Provenance.operationsFor ev)

    let unverified = FaultResolved(finding.Id, { Timestamp = at; Kind = ResolvedManually; Action = None; Verified = false })
    Assert.Equal<string list>([ "resolved" ], Provenance.operationsFor unverified)

[<Fact>]
let ``a human acknowledgement is a reviewed contribution outside any execution`` () =
    let acknowledgedAt = at.AddMinutes 30.0
    let key = Provenance.outsideExecutionKey acknowledgedAt kevin
    Assert.Matches("^CTB-20260926-[0-9a-f]{8}$", key)

    let acknowledgement = FaultAcknowledged(finding.Id, Operator, acknowledgedAt) |> Provenance.attribute key kevin None |> ok
    let accumulated = ProvenanceHistory.forFault finding.Id (history @ [ acknowledgement ])
    let reviewers = Provenance.withRole "reviewed" accumulated.Block
    Assert.Equal<string list>([ key ], keys reviewers)
    Assert.Equal(kevin, reviewers.Head.Actor)
    // Humans carry no provider/model/runtime.
    Assert.DoesNotContain("\"provider\"", (JsonNode.Parse acknowledgement.Provenance.Value.Json).["contributions"].[key].ToJsonString())
    // The serialized event keeps the role category alongside the identity.
    let payload = Serialization.attributedEvent Redaction.defaultRules (EventId "E-ACK") acknowledgement
    Assert.Contains("\"acknowledgedBy\":\"Operator\"", payload)
    Assert.Contains(key, payload)

[<Fact>]
let ``escalation, reopening and supersession append their actors when known`` () =
    let escalate = FaultEscalated(finding.Id, FaultSeverity.Error, FaultSeverity.Critical, at.AddHours 3.0) |> Provenance.attribute exeB1 claude None |> ok
    let reopen = FaultReopened(finding.Id, at.AddHours 4.0, "recurred") |> Provenance.attribute exeB1 claude None |> ok
    let supersede = FaultSuperseded(finding.Id, FaultId "SF-0002", at.AddHours 5.0) |> Provenance.attribute exeA2 codex None |> ok
    let accumulated = ProvenanceHistory.forFault finding.Id (history @ [ escalate; reopen; supersede ])
    Assert.Empty accumulated.Conflicts

    let entry = Provenance.contributions accumulated.Block |> List.find (fun c -> c.Key = exeB1)
    Assert.Equal<string list>([ "modified" ], entry.Operations)
    Assert.Equal(Some "2026-09-26T13:00:00.000Z", entry.Last)

    let codexEntry = Provenance.contributions accumulated.Block |> List.find (fun c -> c.Key = exeA2)
    Assert.Equal<string list>([ "remediated"; "superseded" ], codexEntry.Operations)

    // Unknown actor for an unattributed lifecycle event: nothing added, nothing inferred.
    let anonymous = Provenance.unattributed (FaultRepeated(finding.Id, at.AddHours 6.0))
    let unchanged = ProvenanceHistory.forFault finding.Id (history @ [ escalate; reopen; supersede; anonymous ])
    Assert.Equal(accumulated.Block, unchanged.Block)

[<Fact>]
let ``two executions of the same agent stay two contributions`` () =
    let discoveredByCodex = Provenance.discovery exeA1 codex None [] finding |> ok
    let events = [ Provenance.attach discoveredByCodex (FaultRecorded finding); remediation ]
    let accumulated = ProvenanceHistory.forFault finding.Id events
    let byCodex = Provenance.contributions accumulated.Block |> List.filter (fun c -> c.Actor.Id = "openai/codex")
    Assert.Equal<string list>([ exeA1; exeA2 ], keys byCodex)

[<Fact>]
let ``re-attributing an execution is refused and reported, never merged`` () =
    let impostor =
        RecoveryStarted(finding.Id, attempt 2 Agent (at.AddHours 2.0)) |> Provenance.attribute exeA2 claude None |> ok

    let accumulated = ProvenanceHistory.forFault finding.Id (history @ [ impostor ])
    Assert.Single accumulated.Conflicts |> ignore
    Assert.Contains("refusing to re-attribute", accumulated.Conflicts.Head)
    Assert.Equal(codex, (Provenance.withRole "remediated" accumulated.Block).Head.Actor)

[<Fact>]
let ``a second or late created is refused`` () =
    let second = Provenance.append (Provenance.contribution exeB1 claude (at.AddHours 1.0) [ "created" ]) discovered
    Assert.True(Result.isError second)

    let early = Provenance.build [ Provenance.contribution exeB1 claude (at.AddHours 1.0) [ "reviewed" ] ] [] |> ok
    let late = Provenance.append (Provenance.contribution exeA1 gemini (at.AddHours 2.0) [ "created" ]) early
    Assert.True(Result.isError late)

[<Fact>]
let ``appending the identical contribution is idempotent`` () =
    let contribution = Provenance.contribution exeA2 codex (at.AddHours 1.0) [ "remediated" ]
    let once = Provenance.append contribution discovered |> ok
    let twice = Provenance.append contribution once |> ok
    Assert.Equal(once.Json, twice.Json)
    Assert.Empty(Provenance.preservationViolations discovered twice)

// ------------------------------------------------------------ identity + unknown

[<Fact>]
let ``an undeclared actor is recorded as unknown, never guessed`` () =
    // AEG-PROV-010.
    let identity = ProvenanceIdentity.fromDeclarations (fun _ -> None)
    Assert.Equal(ProvenanceIdentity.unknownActor, identity.Actor)
    Assert.Equal(None, identity.Execution)
    let key = ProvenanceIdentity.keyFor "op-1" at identity |> ok
    Assert.StartsWith("CTB-20260926-", key)

    let block = Provenance.discovery key identity.Actor None [] finding |> ok
    Assert.Equal(ProvenanceVerdict.Supported [], Provenance.classify block.Json)
    Assert.Equal("unknown", (Provenance.originator block |> Option.get).Actor.Kind)

[<Fact>]
let ``declared identity and execution come only from the whitelisted variables`` () =
    let env =
        Map [ "ROS_ACTOR_KIND", "agent"
              "ROS_TELEMETRY_PROVIDER", "anthropic"
              "ROS_TELEMETRY_RUNTIME", "claude-code"
              "ROS_EXECUTION_ID", exeB1
              "OLLAMA_HOST", "http://localhost:11434" ]

    let identity = ProvenanceIdentity.fromDeclarations (fun name -> Map.tryFind name env)
    Assert.Equal(claude, identity.Actor)
    Assert.Equal(Some exeB1, identity.Execution)
    Assert.Equal(Ok exeB1, ProvenanceIdentity.keyFor "op-1" at identity)

    // An agent with no declared execution is keyed by its operation.
    let noExecution = { identity with Execution = None }
    Assert.Equal(Ok "EXT-op.op_2f1", ProvenanceIdentity.keyFor "op/1" at noExecution)

    // A human omits provider/model/runtime.
    let human = ProvenanceIdentity.fromDeclarations (fun name -> Map.tryFind name (Map [ "ROS_ACTOR_KIND", "human"; "ROS_ACTOR", "kevin" ]))
    Assert.Equal(kevin, human.Actor)

// ----------------------------------------------------- legacy + serialization

[<Fact>]
let ``a legacy event without provenance stays valid and reads as unattributed`` () =
    // AEG-PROV-008.
    let legacy = Serialization.event Redaction.defaultRules (EventId "E-OLD") (FaultRecorded finding)
    Assert.DoesNotContain("\"provenance\"", legacy)
    Assert.Equal(Ok None, Store.provenanceOf legacy)

    let projected = Store.provenanceHistory [ legacy ] |> ok
    let entry = projected[finding.Id.Value]
    Assert.False entry.Attributed
    Assert.True(Provenance.isUnattributed entry.Block)
    Assert.Equal(None, Provenance.originator entry.Block)

    // An old payload predating every optional field is equally readable.
    let ancient = """{"schema":"aegis/event/v1","eventId":"01E0","eventType":"FaultRecorded"}"""
    Assert.Equal(Ok None, Store.provenanceOf ancient)

[<Fact>]
let ``an event without provenance serializes exactly as before`` () =
    // AEG-PROV-012.
    for ev in history |> List.map (fun attributed -> attributed.Event) do
        Assert.Equal(
            Serialization.event Redaction.defaultRules (EventId "E1") ev,
            Serialization.attributedEvent Redaction.defaultRules (EventId "E1") (Provenance.unattributed ev)
        )

[<Fact>]
let ``serialization round-trips the block verbatim, including unknown fields`` () =
    // AEG-PROV-001, AEG-PROV-007.
    let preserved =
        (fixture "cases.json").["cases"].AsArray()
        |> Seq.find (fun item -> item["name"].GetValue<string>() = "unknown-fields-preserved")

    let block = Provenance.receive (preserved["block"].ToJsonString()) |> ok

    // The case's future `attestation.signature` field matches Aegis's default
    // `credentials` redaction rule, so with the default rules it is refused
    // rather than redacted in place (provenance is carried verbatim)...
    Assert.True(Result.isError (Provenance.attachWith Redaction.defaultRules block (FaultRecorded finding)))

    // ...and with rules that do not match, it round-trips verbatim.
    let noRules: Redaction.Rule list = []
    let payload = Serialization.attributedEvent noRules (EventId "E2") (Provenance.attach block (FaultRecorded finding))
    Assert.Equal("aegis/event/v1", (JsonNode.Parse payload).["schema"].GetValue<string>())

    match Store.provenanceOf payload with
    | Ok(Some read) ->
        Assert.Equal(block, read)
        Assert.True(JsonNode.DeepEquals(preserved["block"], JsonNode.Parse read.Json))
    | other -> failwith $"expected the block back, got {other}"

    // The fault form carries it too, under the fault schema.
    let faultPayload = Serialization.attributedFault noRules finding block
    Assert.Equal("aegis/fault/v1", (JsonNode.Parse faultPayload).["schema"].GetValue<string>())
    Assert.Equal(Ok(Some block), Store.provenanceOf faultPayload)

[<Fact>]
let ``an unsupported major is carried verbatim and never merged`` () =
    let future = """{"schema":"praxis.provenance/2","contributions":[{"totally":"different"}],"whatever":true}"""
    let block = Provenance.receive future |> ok
    Assert.False block.IsSupported
    Assert.True(Result.isError (Provenance.append (Provenance.contribution exeA2 codex at [ "remediated" ]) block))

    let carried = RecoveryStarted(finding.Id, attempt 1 Agent at) |> Provenance.attach block
    let payload = Serialization.attributedEvent Redaction.defaultRules (EventId "E3") carried
    Assert.True(JsonNode.DeepEquals(JsonNode.Parse future, (JsonNode.Parse payload).["provenance"]))

    let accumulated = ProvenanceHistory.forFault finding.Id (history @ [ carried ])
    Assert.Equal<ProvenanceBlock list>([ block ], accumulated.Carried)
    Assert.Equal((ProvenanceHistory.forFault finding.Id history).Block, accumulated.Block)

[<Fact>]
let ``malformed provenance is rejected at capture and append time`` () =
    // AEG-PROV-007: including credential-like values anywhere.
    Assert.True(Result.isError (Provenance.receive """{"schema":"praxis.provenance/1"}"""))
    Assert.True(Result.isError (Provenance.receive "not json"))

    let leaky = Provenance.contribution exeA2 codex at [ "remediated" ]
    let withToken = { leaky with Reason = Some "used ghp_0123456789abcdefghijABCDEFGHIJ0123" }
    Assert.True(Result.isError (Provenance.append withToken discovered))

    let agentWithoutExecution = Provenance.contribution "CTB-20260926-11111111" codex at [ "remediated" ]
    Assert.True(Result.isError (Provenance.append agentWithoutExecution discovered))

    // A stored event whose provenance is malformed is reported, not dropped.
    let tampered = """{"schema":"aegis/event/v1","eventId":"E9","eventType":"FaultRecorded","faultId":"SF-0001","provenance":{"schema":"praxis.provenance/1"}}"""

    match Store.provenanceOf tampered with
    | Error(Store.Malformed detail) -> Assert.Contains("contributions is required", detail)
    | other -> failwith $"expected Malformed, got {other}"

    Assert.True(Result.isError (Store.provenanceHistory [ tampered ]))

[<Fact>]
let ``capture attributes the recorded fault to its discoverer`` () =
    let collector = Sinks.Collector()
    let rejected = Collections.Generic.List<string>()

    let config =
        { Aegis.configure "Chrona" None [ collector.Sink() ] with
            Persistence = Blocking
            Now = fun () -> at
            Fallback = rejected.Add }

    let scope = Aegis.scope config "Chrona.Query.Build" Map.empty
    let classify scope ex = { Aegis.faultOf config scope (FaultCode "SEC") SecurityFailure FaultSeverity.Critical ApplicationUnsafe Persistent ManualIntervention "blocked" ex with Diagnostics = finding.Diagnostics }
    let result = Aegis.captureAttributed config scope classify (Provenance.discovery exeA1 gemini None []) (fun () -> failwith "boom")
    Assert.True(Result.isError result)

    let stored = collector.Events |> List.exactlyOne
    let block = Store.provenanceOf stored |> ok |> Option.get
    Assert.Equal(exeA1, (Provenance.originator block |> Option.get).Key)

    // A refused attribution still records the fault, unattributed, and says why.
    let refuse (_: Fault) : Result<ProvenanceBlock, string> = Error "no execution for an agent"
    Aegis.captureAttributed config scope classify refuse (fun () -> failwith "boom") |> ignore
    Assert.Equal(2, collector.Events.Length)
    Assert.Equal(Ok None, Store.provenanceOf (collector.Events |> List.last))
    Assert.Contains("provenance rejected", Assert.Single(rejected))

// --------------------------------------------------------------- lineage

[<Fact>]
let ``affected-artifact lineage is not authorship`` () =
    // AEG-PROV-005.
    let block = Provenance.discovery exeA1 gemini None [ "praxis:RQ-APP-2026-A001"; "file:src/Query.fs" ] finding |> ok
    Assert.Equal<string list>([ "git:commit/5e1f0c2"; "praxis:RQ-APP-2026-A001"; "file:src/Query.fs" ], Provenance.lineage block)
    Assert.Equal<string list>([ exeA1 ], Provenance.contributions block |> keys)
    Assert.Equal(gemini, (Provenance.originator block |> Option.get).Actor)

    // The commit's author (another agent) is never merged into the finding.
    let commitProvenance = Provenance.build [ Provenance.contribution exeB1 claude (at.AddHours -1.0) [ "created" ] ] [] |> ok
    Assert.Equal(claude, (Provenance.originator commitProvenance |> Option.get).Actor)
    Assert.DoesNotContain("anthropic/claude-code", block.Json)

// --------------------------------------------------------------- replays

let private stepsFor (record: string) =
    (fixture "echelon-chain.json").["steps"].AsArray()
    |> Seq.filter (fun step -> step["record"].GetValue<string>() = record)
    |> Seq.toList

let private applyStep (block: ProvenanceBlock) (step: JsonNode) =
    match step["append"] with
    | null ->
        let references = step["lineage"].AsArray() |> Seq.map (fun node -> node.GetValue<string>()) |> Seq.toList
        Provenance.addLineage references block |> ok
    | append ->
        Provenance.appendJson (append["key"].GetValue<string>()) (append["contribution"].ToJsonString()) block
        |> ok
        |> fst

[<Fact>]
let ``the aegis finding SF-0001 replays through Aegis events with its discovered, remediated and validated roles`` () =
    // AEG-PROV-003, AEG-PROV-011: each chain step becomes the Aegis event that
    // records it, is serialized, stored, and folded back from the store.
    let steps = stepsFor "aegis:finding/SF-0001"

    let eventFor (step: JsonNode) =
        let append = step["append"]
        let contribution = append["contribution"]
        let atText = contribution["at"].GetValue<string>()
        let when' = DateTimeOffset.Parse atText
        let operations = contribution["operations"].AsArray() |> Seq.map (fun node -> node.GetValue<string>()) |> Seq.toList

        match operations with
        | ops when List.contains "discovered" ops -> FaultRecorded { finding with Timestamp = when' }
        | ops when List.contains "remediated" ops -> RecoveryStarted(finding.Id, attempt 1 Agent when')
        | ops when List.contains "validated" ops ->
            FaultResolved(finding.Id, { Timestamp = when'; Kind = ResolvedManually; Action = None; Verified = true })
        | ops -> failwith $"unexpected operations {ops}"

    // A lineage step belongs to the event recorded just before it.
    let events =
        steps
        |> List.fold
            (fun (acc: (AegisEvent * ProvenanceBlock) list) step ->
                match step["append"], acc with
                | null, (ev, block) :: rest -> (ev, applyStep block step) :: rest
                | null, [] -> failwith "lineage before any event"
                | _, _ -> (eventFor step, applyStep Provenance.empty step) :: acc)
            []
        |> List.rev

    let payloads =
        events
        |> List.mapi (fun index (ev, block) -> Serialization.attributedEvent Redaction.defaultRules (EventId $"E{index}") (Provenance.attach block ev))

    let accumulated = (Store.provenanceHistory payloads |> ok)[finding.Id.Value]
    Assert.True accumulated.Attributed
    Assert.Empty accumulated.Conflicts

    let expect = (fixture "echelon-chain.json").["expect"]
    let roles = expect["roles"].["aegis:finding/SF-0001"].AsObject()

    for pair in roles do
        let expected = pair.Value.AsArray() |> Seq.map (fun node -> node.GetValue<string>()) |> Seq.toList
        Assert.Equal<string list>(expected, Provenance.withRole pair.Key accumulated.Block |> keys)

    let origin = Provenance.originator accumulated.Block |> Option.get
    Assert.Equal(expect["originators"].["aegis:finding/SF-0001"].["key"].GetValue<string>(), origin.Key)
    Assert.Equal(expect["originators"].["aegis:finding/SF-0001"].["actorId"].GetValue<string>(), origin.Actor.Id)
    Assert.Equal<string list>([ "git:commit/5e1f0c2"; "dokimos:observation/OBS-2026-0001" ], Provenance.lineage accumulated.Block)

    // The same fold over the in-memory events agrees with the stored one.
    let inMemory = ProvenanceHistory.forFault finding.Id (events |> List.map (fun (ev, block) -> Provenance.attach block ev))
    Assert.Equal(accumulated.Block, inMemory.Block)

    // And it is a faithful extension of the discovery step alone.
    Assert.Empty(Provenance.preservationViolations (snd events.Head) accumulated.Block)

[<Fact>]
let ``the whole Echelon chain replays through the Aegis codec with every expectation`` () =
    // AEG-PROV-011: the codec reproduces the cross-system scenario, keeping
    // each record's own originator and never merging authors through lineage.
    let chain = fixture "echelon-chain.json"
    let expect = chain["expect"]

    let records =
        chain["steps"].AsArray()
        |> Seq.fold
            (fun (state: Map<string, ProvenanceBlock>) step ->
                let record = step["record"].GetValue<string>()
                let current = state |> Map.tryFind record |> Option.defaultValue Provenance.empty
                Map.add record (applyStep current step) state)
            Map.empty

    for pair in expect["originators"].AsObject() do
        let origin = Provenance.originator records[pair.Key] |> Option.get
        Assert.Equal(pair.Value["key"].GetValue<string>(), origin.Key)
        Assert.Equal(pair.Value["actorId"].GetValue<string>(), origin.Actor.Id)

    for record in expect["roles"].AsObject() do
        for role in record.Value.AsObject() do
            let expected = role.Value.AsArray() |> Seq.map (fun node -> node.GetValue<string>()) |> Seq.toList
            Assert.Equal<string list>(expected, Provenance.withRole role.Key records[record.Key] |> keys)

    let rec reach (seen: Set<string>) (record: string) =
        match Map.tryFind record records with
        | None -> seen
        | Some block ->
            Provenance.lineage block
            |> List.filter (fun reference -> not (seen.Contains reference))
            |> List.fold (fun acc reference -> reach (Set.add reference acc) reference) seen

    let reached = reach Set.empty (expect["lineageFrom"].GetValue<string>())

    for reference in expect["lineageReaches"].AsArray() do
        Assert.Contains(reference.GetValue<string>(), reached)

    let oneAgent = expect["distinctExecutionsOfOneAgent"]
    let actorId = oneAgent["actorId"].GetValue<string>()

    let executions =
        records
        |> Map.toList
        |> List.collect (fun (_, block) -> Provenance.contributions block)
        |> List.filter (fun c -> c.Actor.Id = actorId)
        |> List.map (fun c -> c.Key)
        |> List.distinct
        |> List.sort

    Assert.Equal<string list>(oneAgent["keys"].AsArray() |> Seq.map (fun node -> node.GetValue<string>()) |> Seq.toList |> List.sort, executions)

    let originators = records |> Map.toList |> List.choose (fun (_, block) -> Provenance.originator block) |> List.length
    Assert.Equal(expect["chainOriginatorCount"].GetValue<int>(), originators)

    for pair in records do
        Assert.Equal(ProvenanceVerdict.Supported [], Provenance.classify pair.Value.Json)

// --------------------------------------------------------------- Tutela

[<Fact>]
let ``the Tutela projection carries the block as contributionProvenance, never as provenance or producerIdentity`` () =
    // AEG-PROV-009.
    let accumulated = ProvenanceHistory.forFault finding.Id history
    let attributed = Tutela.tryProjectAttributedFault "1.1.0" (Some accumulated.Block) finding |> ok
    Assert.Equal(Tutela.tryProjectFault "1.1.0" finding |> ok, attributed.Evidence)

    let json = JsonNode.Parse(Tutela.toJson attributed)
    Assert.Equal("tutela/evidence/v1", json["schema"].GetValue<string>())
    Assert.True(JsonNode.DeepEquals(JsonNode.Parse accumulated.Block.Json, json["contributionProvenance"]))
    Assert.Null(json["provenance"])
    Assert.Null(json["producerIdentity"])
    Assert.Equal("EchelonFoundry.Aegis.Core/1.1.0", json["producer"].GetValue<string>())
    Assert.DoesNotContain("never-in-provenance", json.ToJsonString())

    // Without provenance the field is absent, and a non-security fault still is not evidence.
    let plain = JsonNode.Parse(Tutela.toJson { attributed with ContributionProvenance = None })
    Assert.Null(plain["contributionProvenance"])
    Assert.Equal(Error Tutela.NotSecurityRelevant, Tutela.tryProjectAttributedFault "1.1.0" None { finding with Category = DomainFailure })

// ------------------------------------------------ contract revision 1.1

let private env (pairs: (string * string) list) =
    let map = Map pairs
    fun name -> Map.tryFind name map

[<Fact>]
let ``rule 8 - an identity-less process never inherits a run from ROS_EXECUTION_ID`` () =
    // Finding (a): a service started from an agent shell must not attribute
    // every fault to that agent's execution.
    let identity = ProvenanceIdentity.fromDeclarations (env [ "ROS_EXECUTION_ID", exeB1 ])
    Assert.Equal(ProvenanceIdentity.unknownActor, identity.Actor)
    Assert.Equal(None, identity.Execution)
    let key = ProvenanceIdentity.keyFor "op-1" at identity |> ok
    Assert.NotEqual<string>(exeB1, key)
    Assert.StartsWith("CTB-", key)

    // Declaring a kind or an id makes the run the process's own assertion.
    Assert.Equal(Some exeB1, (ProvenanceIdentity.fromDeclarations (env [ "ROS_EXECUTION_ID", exeB1; "ROS_ACTOR_KIND", "agent" ])).Execution)
    Assert.Equal(Some exeB1, (ProvenanceIdentity.fromDeclarations (env [ "ROS_EXECUTION_ID", exeB1; "ROS_ACTOR", "acme/bot" ])).Execution)

[<Fact>]
let ``rule 1 - a declared kind with a trailing newline is not a declaration`` () =
    // Finding (b).
    for kind in [ "human\n"; "x-bot\n"; "agent\n" ] do
        let identity = ProvenanceIdentity.fromDeclarations (env [ "ROS_ACTOR_KIND", kind; "ROS_EXECUTION_ID", exeB1 ])
        Assert.Equal("unknown", identity.Actor.Kind)
        Assert.Equal(None, identity.Execution)

    let withNewline = { Provenance.contribution "CTB-20260926-aaaaaaaa" { kevin with Kind = "human\n" } at [ "reviewed" ] with Reason = None }
    Assert.True(Result.isError (Provenance.append withNewline discovered))
    Assert.True(Result.isError (Provenance.append (Provenance.contribution (exeB1 + "\n") claude at [ "reviewed" ]) discovered))
    Assert.True(Result.isError (Provenance.append (Provenance.contribution exeB1 claude (at.AddHours 1.0) [ "reviewed\n" ]) discovered))

[<Fact>]
let ``identity discovery reads only variables in the vendored identity environment list`` () =
    let listed =
        (fixture "identity-environment.json").["variables"].AsArray()
        |> Seq.map (fun node -> node.GetValue<string>())
        |> Set.ofSeq

    let read = Collections.Generic.HashSet<string>()
    ProvenanceIdentity.fromDeclarations (fun name -> read.Add name |> ignore; None) |> ignore
    Assert.NotEmpty read
    Assert.Empty(read |> Seq.filter (fun name -> not (listed.Contains name)))

[<Fact>]
let ``rule 2 - timestamps are calendar-valid and ordered at millisecond precision`` () =
    let block at = sprintf """{"schema":"praxis.provenance/1","contributions":{"CTB-20260926-aaaaaaaa":{"operations":["created"],"at":"%s","actor":{"kind":"human","id":"kevin"}}}}""" at

    for invalid in [ "2026-02-30T08:00:00.000Z"; "2026-09-26T24:00:00.000Z"; "0000-01-01T00:00:00.000Z"; "2026-09-26T08:00:00.000Z\n"; "2026-09-26T08:60:00.000Z" ] do
        Assert.True(Result.isError (Provenance.receive (block (invalid.Replace("\n", "\\n")))), invalid)

    for valid in [ "9999-12-31T23:59:59.999999999Z"; "2024-02-29T00:00:00Z"; "2026-09-26T08:00:00.0009Z" ] do
        Assert.True(Result.isOk (Provenance.receive (block valid)), valid)

    // 08:00:00.0009 truncates to 08:00:00.000, so a contribution at .000 does not precede the creation.
    let created = Provenance.receive (block "2026-09-26T08:00:00.0009Z") |> ok
    let same = Provenance.appendJson "CTB-20260926-bbbbbbbb" """{"operations":["reviewed"],"at":"2026-09-26T08:00:00.000Z","actor":{"kind":"human","id":"ana"}}""" created
    Assert.True(Result.isOk same)

[<Fact>]
let ``rule 3 - null never means absent`` () =
    for fieldJson in [ "\"last\":null"; "\"reason\":null"; "\"evidence\":null" ] do
        let contribution = sprintf """{"operations":["reviewed"],"at":"2026-09-26T10:00:00.000Z","actor":{"kind":"human","id":"kevin"},%s}""" fieldJson
        Assert.True(Result.isError (Provenance.appendJson "CTB-20260926-aaaaaaaa" contribution discovered), fieldJson)

    Assert.True(Result.isError (Provenance.appendJson "CTB-20260926-aaaaaaaa" """{"operations":["reviewed"],"at":"2026-09-26T10:00:00.000Z","actor":{"kind":"human","id":"kevin","provider":null}}""" discovered))

[<Fact>]
let ``rule 4 - an append never returns a block classify would reject`` () =
    // Credential in an unknown field of the incoming contribution.
    let leaky = """{"operations":["reviewed"],"at":"2026-09-26T10:00:00.000Z","actor":{"kind":"human","id":"kevin"},"x-note":"AKIAABCDEFGHIJKLMNOP"}"""
    Assert.True(Result.isError (Provenance.appendJson "CTB-20260926-aaaaaaaa" leaky discovered))

    // A contribution dated before the creation.
    let early = Provenance.append (Provenance.contribution exeB1 claude (at.AddHours -1.0) [ "reviewed" ]) discovered
    Assert.True(Result.isError early)

    // `created` merged into an existing non-creator entry that has earlier contributions before it.
    let history =
        Provenance.build
            [ Provenance.contribution exeB1 claude at [ "reviewed" ]
              Provenance.contribution exeA2 codex (at.AddHours 1.0) [ "modified" ] ]
            []
        |> ok

    Assert.True(Result.isError (Provenance.append (Provenance.contribution exeA2 codex (at.AddHours 2.0) [ "created" ]) history))

    // Everything that is accepted classifies as supported.
    let accepted = Provenance.append (Provenance.contribution exeA2 codex (at.AddHours 2.0) [ "remediated" ]) discovered |> ok
    Assert.Equal(ProvenanceVerdict.Supported [], Provenance.classify accepted.Json)

[<Fact>]
let ``rule 5 - merging a key keeps incoming unknown fields and the later last`` () =
    // Finding (c): later events' extension fields and `last` survive the fold.
    let first = """{"operations":["remediated"],"at":"2026-09-26T10:00:00.000Z","actor":{"kind":"agent","id":"openai/codex","provider":"openai","model":"gpt-5-codex","runtime":"codex"},"x-attempt":"1"}"""
    let second = """{"operations":["resolved"],"at":"2026-09-26T10:30:00.000Z","last":"2026-09-26T11:00:00.000Z","actor":{"kind":"agent","id":"openai/codex","provider":"openai","model":"gpt-5-codex","runtime":"codex"},"x-attempt":"2","x-ticket":"SEC-7"}"""
    let blockOf json = sprintf """{"schema":"praxis.provenance/1","contributions":{"%s":%s}}""" exeA2 json |> Provenance.receive |> ok

    let events =
        [ Provenance.attach discovered (FaultRecorded finding)
          Provenance.attach (blockOf first) (RecoveryStarted(finding.Id, attempt 1 Agent (at.AddHours 1.0)))
          Provenance.attach (blockOf second) (FaultResolved(finding.Id, { Timestamp = at.AddHours 1.5; Kind = ResolvedManually; Action = None; Verified = false })) ]

    let accumulated = ProvenanceHistory.forFault finding.Id events
    Assert.Empty accumulated.Conflicts
    let entry = (JsonNode.Parse accumulated.Block.Json).["contributions"].[exeA2]
    Assert.Equal("1", entry["x-attempt"].GetValue<string>()) // existing wins on conflict
    Assert.Equal("SEC-7", entry["x-ticket"].GetValue<string>())
    Assert.Equal("2026-09-26T11:00:00.000Z", entry["last"].GetValue<string>())
    Assert.Equal<string list>([ "remediated"; "resolved" ], (Provenance.contributions accumulated.Block |> List.find (fun c -> c.Key = exeA2)).Operations)

[<Fact>]
let ``rule 5 - an actor with unknown identity cannot extend a known actor's entry`` () =
    let anonymousAgent = ProvenanceIdentity.agent "unknown" "unknown" "unknown" "unknown"
    Assert.True(Result.isError (Provenance.append (Provenance.contribution exeA1 anonymousAgent (at.AddHours 1.0) [ "modified" ]) discovered))
    Assert.True(Result.isError (Provenance.append (Provenance.contribution exeA1 ProvenanceIdentity.unknownActor (at.AddHours 1.0) [ "modified" ]) discovered))

[<Fact>]
let ``rule 6 - operation keys are escaped injectively`` () =
    Assert.Equal(Ok "EXT-op.op_201", Provenance.operationKey "op 1")
    Assert.Equal(Ok "EXT-op.gh_2f99", Provenance.operationKey "gh/99")
    Assert.Equal(Ok "EXT-op.a_5fb", Provenance.operationKey "a_b")
    Assert.Equal(Ok "EXT-op.caf_c3_a9", Provenance.operationKey "caf\u00e9")
    let distinct = [ "a b"; "a/b"; "a_b"; "a-b"; "a_20b"; "a.b"; "a_2eb" ] |> List.map (Provenance.operationKey >> ok)
    Assert.Equal(distinct.Length, (List.distinct distinct).Length)
    for key in distinct do
        Assert.Equal("foreign-execution", Provenance.keyKind key)

// --------------------------------------------------- finding (d): serialization

let private legacyFaultForm (payload: string) (f: Fault) =
    payload
        .Replace($"\"schema\":\"{Schema.Event}\"", $"\"schema\":\"{Schema.Fault}\"")
        .Replace($"\"eventId\":\"{f.Id.Value}\",", "")
        .Replace("\"eventType\":\"FaultRecorded\",", "")

[<Fact>]
let ``the fault form is built structurally, never by rewriting text inside a carried block`` () =
    // Unchanged output for a fault without provenance.
    let plain = Serialization.fault Redaction.defaultRules finding
    Assert.Equal(legacyFaultForm (Serialization.event Redaction.defaultRules (EventId finding.Id.Value) (FaultRecorded finding)) finding, plain)

    // An unsupported-major block whose text contains exactly what the old
    // string replacement removed must survive verbatim.
    let future =
        sprintf """{"schema":"praxis.provenance/2","eventType":"FaultRecorded","eventId":"%s","note":"aegis/event/v1","x":1}""" finding.Id.Value

    let block = Provenance.receive future |> ok
    let payload = Serialization.attributedFault Redaction.defaultRules finding block
    let node = JsonNode.Parse payload
    Assert.Equal("aegis/fault/v1", node["schema"].GetValue<string>())
    Assert.Null(node["eventId"])
    Assert.Null(node["eventType"])
    Assert.True(JsonNode.DeepEquals(JsonNode.Parse future, node["provenance"]))

[<Fact>]
let ``a block matching a redaction rule is rejected at attach time and never written`` () =
    // Key-name rules apply to member names (finding 8, contract 1.2).
    let tokenField =
        Provenance.receive """{"schema":"praxis.provenance/1","contributions":{},"x-api_key-hint":"see vault"}""" |> ok

    let sessionInContribution =
        Provenance.receive (sprintf """{"schema":"praxis.provenance/1","contributions":{"%s":{"operations":["created"],"at":"2026-09-26T09:00:00.000Z","actor":{"kind":"human","id":"kevin"},"x-session-ref":"S-1"}}}""" "CTB-20260926-aaaaaaaa")
        |> ok

    for block in [ tokenField; sessionInContribution ] do
        Assert.NotEmpty(Provenance.redactionFindings Redaction.defaultRules block)

        match Provenance.attachWith Redaction.defaultRules block (FaultRecorded finding) with
        | Error message -> Assert.Contains("redaction rule 'credentials'", message)
        | Ok _ -> failwith "expected the block to be rejected"

    // A custom application rule applies to field names too, never to free text.
    let customerRule: Redaction.Rule =
        { Name = "customer"
          AppliesTo = fun (text: string) -> text.Contains("acme-customer") }

    let custom = Redaction.withRule customerRule Redaction.defaultRules
    let customerField = Provenance.receive """{"schema":"praxis.provenance/1","contributions":{},"x-acme-customer":"17"}""" |> ok
    let customerEvidence = Provenance.discovery exeA1 gemini None [ "crm:acme-customer-17" ] finding |> ok
    Assert.Empty(Provenance.redactionFindings Redaction.defaultRules customerField)
    Assert.NotEmpty(Provenance.redactionFindings custom customerField)
    Assert.Empty(Provenance.redactionFindings custom customerEvidence)

    // Serialization never writes the matching block, and says so.
    let payload = Serialization.attributedEvent Redaction.defaultRules (EventId "E-R") (Provenance.attach tokenField (FaultRecorded finding))
    Assert.DoesNotContain("see vault", payload)
    let node = JsonNode.Parse payload
    Assert.Null(node["provenance"])
    Assert.Contains("credentials", node["provenanceRejected"].GetValue<string>())

    // reportAttributed rejects before anything reaches a sink.
    let collector = Sinks.Collector()
    let config = { Aegis.configure "Chrona" None [ collector.Sink() ] with Persistence = Blocking; Now = fun () -> at }
    Assert.True(Result.isError (Aegis.reportAttributed config (Provenance.attach tokenField (FaultRecorded finding))))
    Assert.Empty collector.Events
    Assert.True(Result.isOk (Aegis.reportAttributed config (Provenance.attach discovered (FaultRecorded finding))))
    Assert.Single collector.Events |> ignore

    // A clean discovery block has no findings.
    Assert.Empty(Provenance.redactionFindings Redaction.defaultRules discovered)

// ------------------------------------------------ contract revision 1.2

/// An unpaired UTF-16 surrogate, built at run time (a literal could be
/// re-encoded by the compiler).
let private lone (code: int) = string (char code)

let private verdictName verdict =
    match verdict with
    | ProvenanceVerdict.Supported _ -> "supported"
    | ProvenanceVerdict.Unsupported _ -> "unsupported"
    | ProvenanceVerdict.Malformed _ -> "malformed"

[<Fact>]
let ``1.2 rule 1 - every vendored text case reaches the reference verdict through classify and receive`` () =
    // Findings 5 and 10: duplicate member names and unpaired surrogates are
    // malformed, whatever the major version, and neither function throws.
    let cases = (fixture "text-cases.json").["cases"].AsArray()
    Assert.Equal(14, cases.Count)

    let failures =
        [ for item in cases do
              let text = item["text"].GetValue<string>()
              let expected = item["expect"].GetValue<string>()
              let classified = verdictName (Provenance.classify text)

              let received =
                  match Provenance.receive text with
                  | Ok block when block.IsSupported -> "supported"
                  | Ok _ -> "unsupported"
                  | Error _ -> "malformed"

              if classified <> expected || received <> expected then
                  $"{name item}: expected {expected}, classify {classified}, receive {received}" ]

    Assert.Empty failures

[<Fact>]
let ``finding 5 - a duplicate contribution key cannot smuggle an originator past any reader`` () =
    let smuggled =
        """{"schema":"praxis.provenance/1","contributions":{"EXE-A":{"operations":["created"],"at":"2026-09-26T08:00:00.000Z","actor":{"kind":"human","id":"mallory"}},"EXE-A":{"operations":["modified"],"at":"2026-09-26T09:00:00.000Z","actor":{"kind":"human","id":"alice"}}}}"""

    match Provenance.classify smuggled with
    | ProvenanceVerdict.Malformed problems -> Assert.Contains("repeated", String.Join(" ", problems))
    | other -> failwith $"expected malformed, got {other}"

    Assert.True(Result.isError (Provenance.receive smuggled))
    // Appending a contribution given as text with a repeated name is refused too.
    Assert.True(Result.isError (Provenance.appendJson "CTB-20260926-aaaaaaaa" """{"operations":["reviewed"],"at":"2026-09-26T10:00:00.000Z","actor":{"kind":"human","id":"kevin","id":"mallory"}}""" discovered))
    // A stored event carrying it is reported, not read.
    let stored = sprintf """{"schema":"aegis/event/v1","eventId":"E1","eventType":"FaultRecorded","faultId":"SF-0001","provenance":%s}""" smuggled
    Assert.True(Result.isError (Store.provenanceOf stored))

[<Fact>]
let ``finding 10 - classify, receive and append never throw on unpaired surrogates`` () =
    for text in [ "{\"schema\":\"praxis.provenance/2\",\"x-a\":\"\\ud800\"}"
                  "{\"schema\":\"praxis.provenance/1\",\"contributions\":{},\"x-\\udc00\":1}"
                  "{\"schema\":\"praxis.provenance/1\",\"contributions\":{},\"x-a\":\"" + lone 0xD800 + "\"}"
                  "{\"schema\":\"praxis.provenance/1\""
                  null ] do
        Assert.Equal("malformed", verdictName (Provenance.classify text))
        Assert.True(Result.isError (Provenance.receive text))

    // A lone surrogate inside an already-parsed node is malformed too.
    let node = JsonObject()
    node["schema"] <- JsonValue.Create "praxis.provenance/2"
    node["x-a"] <- JsonValue.Create(lone 0xD800)
    Assert.Equal("malformed", verdictName (Provenance.classifyNode node))

    // A contribution built in code with a lone surrogate is refused, never re-encoded.
    let unpaired = { Provenance.contribution exeA2 codex (at.AddHours 1.0) [ "remediated" ] with Reason = Some("fix " + lone 0xD800) }
    Assert.True(Result.isError (Provenance.append unpaired discovered))

[<Fact>]
let ``finding 8 - ordinary finding reasons and evidence pass redaction, real tokens do not`` () =
    // The reviewer's repro (review2/ae.fsx).
    let block reason evidence =
        sprintf
            """{"schema":"praxis.provenance/1","contributions":{"EXE-20260926T000000000Z-a1a1a1a1":{"operations":["created","discovered"],"at":"2026-09-26T00:00:00.000Z","actor":{"kind":"agent","id":"google/gemini-cli","provider":"google","model":"unknown","runtime":"gemini-cli"},"reason":"%s","evidence":["%s"]}},"derivedFrom":["git:commit/5e1f0c2"]}"""
            reason
            evidence

    for reason, evidence in
        [ "Session cookie lacks the Secure flag", "semgrep:rule/x"
          "Hard-coded signing key", "aegis:finding/token-expiry"
          "Password reset link never expires", "x"
          "Missing CSRF check", "sarif:run/7" ] do
        let received = Provenance.receive (block reason evidence) |> ok
        Assert.Empty(Provenance.redactionFindings Redaction.defaultRules received)
        Assert.True(Result.isOk (Provenance.attachWith Redaction.defaultRules received (FaultRecorded finding)), reason)

    // captureAttributed keeps the attribution for such a finding.
    let collector = Sinks.Collector()
    let rejected = Collections.Generic.List<string>()
    let config =
        { Aegis.configure "Chrona" None [ collector.Sink() ] with
            Persistence = Blocking
            Now = fun () -> at
            Fallback = rejected.Add }
    let scope = Aegis.scope config "Chrona.Session" Map.empty
    let classify scope ex = { Aegis.faultOf config scope (FaultCode "SEC") SecurityFailure FaultSeverity.Critical ApplicationUnsafe Persistent ManualIntervention "blocked" ex with Diagnostics = finding.Diagnostics }
    Aegis.captureAttributed config scope classify (Provenance.discovery exeA1 gemini (Some "Session cookie lacks the Secure flag") [ "aegis:finding/token-expiry" ]) (fun () -> failwith "boom") |> ignore
    Assert.Empty rejected
    let stored = Store.provenanceOf (collector.Events |> List.exactlyOne) |> ok |> Option.get
    Assert.Equal(Some "Session cookie lacks the Secure flag", (Provenance.originator stored |> Option.get).Reason)

    // A real token is still refused: at the boundary, on append, and as lineage.
    let token = "ghp_" + String('A', 36)
    Assert.True(Result.isError (Provenance.receive (block token "x")))
    Assert.True(Result.isError (Provenance.discovery exeA1 gemini (Some $"leaked {token}") [] finding))
    Assert.True(Result.isError (Provenance.discovery exeA1 gemini None [ token ] finding))
    Assert.True(Provenance.isCredentialLike ("Authorization: Bearer " + String('a', 24)))

[<Fact>]
let ``1.2 rule 2 - blank and credential checks use ASCII semantics`` () =
    let withId (id: string) =
        let actor = JsonObject()
        actor["kind"] <- JsonValue.Create "human"
        actor["id"] <- JsonValue.Create id
        let entry = JsonObject()
        entry["operations"] <- JsonArray(JsonValue.Create "created")
        entry["at"] <- JsonValue.Create "2026-09-26T08:00:00.000Z"
        entry["actor"] <- actor
        let contributions = JsonObject()
        contributions["CTB-20260926-00000001"] <- entry
        let block = JsonObject()
        block["schema"] <- JsonValue.Create "praxis.provenance/1"
        block["contributions"] <- contributions
        verdictName (Provenance.classifyNode block)

    for content in [ "\u0085"; "\ufeff"; "\u001c"; "\u00a0" ] do
        Assert.Equal("supported", withId content)

    for blank in [ " \t\r\n"; "\u000b\u000c" ] do
        Assert.Equal("malformed", withId blank)

    Assert.True(Provenance.isCredentialLike ("\u00e9bearer " + String('a', 20)))
    Assert.True(Provenance.isCredentialLike ("BeArEr\t" + String('a', 20)))
    Assert.False(Provenance.isCredentialLike ("xbearer " + String('a', 20)))
    Assert.False(Provenance.isCredentialLike ("_bearer " + String('a', 20)))
    Assert.False(Provenance.isCredentialLike ("bearer\u0085" + String('a', 20)))
    Assert.False(Provenance.isCredentialLike ("bearer " + String('\u212a', 20)))

    // Identity declarations: U+0085 is content, ASCII blank is undeclared.
    Assert.Equal("\u0085", (ProvenanceIdentity.fromDeclarations (env [ "ROS_ACTOR_KIND", "human"; "ROS_ACTOR", "\u0085" ])).Actor.Id)
    Assert.Equal("unknown", (ProvenanceIdentity.fromDeclarations (env [ "ROS_ACTOR_KIND", "human"; "ROS_ACTOR", " \t" ])).Actor.Id)

[<Fact>]
let ``1.2 rule 3 - every vendored lineage case reaches the reference result`` () =
    let cases = (fixture "lineage-cases.json").["cases"].AsArray()
    Assert.Equal(8, cases.Count)

    let failures =
        [ for item in cases do
              let expectedOk = item["ok"].GetValue<bool>()
              let references = item["references"].AsArray() |> Seq.toList

              // Aegis's API takes a string list, so a non-string reference
              // is refused by the type system before addLineage is reached.
              let strings =
                  references
                  |> List.map (fun node ->
                      match node.GetValueKind() with
                      | Text.Json.JsonValueKind.String -> Some(node.GetValue<string>())
                      | _ -> None)

              let result =
                  if strings |> List.exists Option.isNone then
                      Error "non-string reference"
                  else
                      Provenance.receive (item["block"].ToJsonString())
                      |> Result.mapError (fun problems -> String.Join("; ", problems))
                      |> Result.bind (Provenance.addLineage (strings |> List.choose id))

              match expectedOk, result with
              | true, Ok block ->
                  let expected = item["derivedFrom"].AsArray() |> Seq.map (fun node -> node.GetValue<string>()) |> Seq.toList

                  if Provenance.lineage block <> expected then
                      $"{name item}: expected {expected}, got {Provenance.lineage block}"
              | false, Error _ -> ()
              | true, Error problem -> $"{name item}: expected ok, got {problem}"
              | false, Ok _ -> $"{name item}: expected a refusal" ]

    Assert.Empty failures

[<Fact>]
let ``1.2 rule 3 - lineage is checked wherever Aegis adds it`` () =
    let token = "ghp_" + String('A', 36)
    let withCommit sha = { finding with Diagnostics = { finding.Diagnostics with Environment = Some { unknownEnvironment with CommitSha = Some sha } } }
    // A credential in the fault's own commit reference refuses the block; nothing is stored.
    Assert.True(Result.isError (Provenance.discovery exeA1 gemini None [] (withCommit token)))
    // A U+0085 commit is content, never silently dropped.
    let nel = Provenance.discovery exeA1 gemini None [] (withCommit "\u0085") |> ok
    Assert.Equal<string list>([ "git:commit/\u0085" ], Provenance.lineage nel)
    Assert.True(Result.isError (Provenance.addLineage [ "RQ-1" + lone 0xD800 ] discovered))
    Assert.True(Result.isError (Provenance.addLineage [ " \t" ] discovered))
    Assert.Equal<string list>([ "git:commit/5e1f0c2"; "RQ-1"; "RQ-2" ], Provenance.addLineage [ "RQ-1"; "RQ-2"; "RQ-1" ] discovered |> ok |> Provenance.lineage)

[<Fact>]
let ``1.2 rule 4 - every vendored envelope key case escapes per code point`` () =
    // Aegis receives no envelopes, but derives keys with the same
    // escapeKeySegment; the v1 envelope rule is applied here to check it.
    let cases = (fixture "envelope-key-cases.json").["cases"].AsArray()
    Assert.Equal(12, cases.Count)

    let unescape (text: string) (field: string) =
        let m = Text.RegularExpressions.Regex.Match(text, $"\"{field}\":\"((?:[^\"\\\\]|\\\\.)*)\"")
        Text.RegularExpressions.Regex.Unescape m.Groups[1].Value

    let failures =
        [ for item in cases do
              let operationId, run =
                  match item["envelope"] with
                  | null -> unescape (item["envelopeText"].GetValue<string>()) "operationId", None
                  | envelope ->
                      let run = envelope["actor"].["runId"]

                      envelope["operationId"].GetValue<string>(),
                      (if run["state"].GetValue<string>() = "known" && not (Provenance.isBlank (run["value"].GetValue<string>())) then
                           Some(run["value"].GetValue<string>())
                       else
                           None)

              let key =
                  match run with
                  | Some value -> Provenance.escapeKeySegment value |> Result.map (fun segment -> $"EXT-run.{segment}")
                  | None -> Provenance.operationKey operationId

              match item["error"], key with
              | null, Ok actual when actual = item["key"].GetValue<string>() ->
                  if Provenance.keyKind actual <> "foreign-execution" then $"{name item}: {actual} is not a valid key"
              | null, other ->
                  let expected = item["key"].GetValue<string>()
                  $"{name item}: expected {expected}, got {other}"
              | _, Error _ -> ()
              | _, Ok actual -> $"{name item}: expected an error, got {actual}" ]

    Assert.Empty failures

[<Fact>]
let ``1.2 rule 4 - dots are escaped, so a run id cannot forge a namespace`` () =
    Assert.Equal(Ok "EXT-op.vigila_2e7", Provenance.operationKey "vigila.7")
    Assert.NotEqual(Provenance.operationKey "a.b", Provenance.operationKey "a_2eb")
    Assert.Equal(Ok "EXT-op.op-_f0_9f_98_80", Provenance.operationKey "op-\U0001F600")
    Assert.NotEqual(Provenance.operationKey "op-\U0001F600", Provenance.operationKey "op-\U0001F601")
    Assert.True(Result.isError (Provenance.operationKey ""))
    Assert.True(Result.isError (Provenance.operationKey("op-" + lone 0xD83D)))
    Assert.Equal(Ok "EXT-github-actions.run_2e7", Provenance.foreignExecutionKey "github-actions" "run.7")
    Assert.Equal(Ok ciRun, Provenance.foreignExecutionKey "github-actions" "run-777-1")
    // An agent whose operation id cannot form a key gets no invented key.
    let agentIdentity = { Actor = codex; Execution = None }
    Assert.True(Result.isError (ProvenanceIdentity.keyFor "" at agentIdentity))

[<Fact>]
let ``1.2 rule 6 - a stored null provenance is malformed, not absent`` () =
    let stored = """{"schema":"aegis/event/v1","eventId":"E1","eventType":"FaultRecorded","faultId":"SF-0001","provenance":null}"""

    match Store.provenanceOf stored with
    | Error(Store.Malformed _) -> ()
    | other -> failwith $"expected Malformed, got {other}"

    Assert.True(Result.isError (Store.provenanceHistory [ stored ]))

[<Fact>]
let ``suspicion - an event written with provenanceRejected is distinguishable from a legacy event`` () =
    let rejectedBlock = Provenance.receive """{"schema":"praxis.provenance/1","contributions":{},"x-api_key-hint":"see vault"}""" |> ok
    let rejected = Serialization.attributedEvent Redaction.defaultRules (EventId "E-REJ") (Provenance.attach rejectedBlock (FaultRecorded finding))
    let legacy = Serialization.event Redaction.defaultRules (EventId "E-OLD") (FaultRecorded finding)

    match Store.storedProvenance rejected with
    | Ok(StoredProvenance.Rejected reason) -> Assert.Contains("credentials", reason)
    | other -> failwith $"expected Rejected, got {other}"

    Assert.Equal(Ok StoredProvenance.Absent, Store.storedProvenance legacy)

    match Store.provenanceOf rejected with
    | Error(Store.Rejected reason) -> Assert.Contains("rejected when written", reason)
    | other -> failwith $"expected Rejected, got {other}"

    Assert.Equal(Ok None, Store.provenanceOf legacy)

    let projected = (Store.provenanceHistory [ legacy; rejected ] |> ok)[finding.Id.Value]
    Assert.False projected.Attributed
    Assert.Single projected.Rejected |> ignore
    Assert.Contains("E-REJ", projected.Rejected.Head)
    let legacyOnly = (Store.provenanceHistory [ legacy ] |> ok)[finding.Id.Value]
    Assert.Empty legacyOnly.Rejected

    // A stored event may not claim both, and the reason must be a string.
    let both = rejected.Replace("\"provenanceRejected\"", "\"provenance\":{\"schema\":\"praxis.provenance/1\",\"contributions\":{}},\"provenanceRejected\"")
    Assert.True(Result.isError (Store.storedProvenance both))
    Assert.True(Result.isError (Store.storedProvenance (legacy.TrimEnd('}') + ",\"provenanceRejected\":7}")))

[<Fact>]
let ``suspicion - the fold preserves unknown top-level fields such as subject`` () =
    let withSubject =
        (sprintf """{"schema":"praxis.provenance/1","contributions":{"%s":{"operations":["created","discovered"],"at":"2026-09-26T09:00:00.000Z","actor":{"kind":"agent","id":"google/gemini-cli","provider":"google","model":"unknown","runtime":"gemini-cli"}}},"subject":"aegis:finding/SF-0001","x-scanner":{"rule":"sql-1"}}""" exeA1)
        |> Provenance.receive
        |> ok

    let later =
        (sprintf """{"schema":"praxis.provenance/1","contributions":{"%s":{"operations":["remediated"],"at":"2026-09-26T10:00:00.000Z","actor":{"kind":"agent","id":"openai/codex","provider":"openai","model":"gpt-5-codex","runtime":"codex"}}},"subject":"aegis:finding/OTHER","x-ticket":"SEC-7"}""" exeA2)
        |> Provenance.receive
        |> ok

    let events = [ Provenance.attach withSubject (FaultRecorded finding); Provenance.attach later (RecoveryStarted(finding.Id, attempt 1 Agent (at.AddHours 1.0))) ]
    let accumulated = ProvenanceHistory.forFault finding.Id events
    let json = JsonNode.Parse accumulated.Block.Json
    Assert.Equal("aegis:finding/SF-0001", json["subject"].GetValue<string>())
    Assert.Equal("sql-1", json["x-scanner"].["rule"].GetValue<string>())
    Assert.Equal("SEC-7", json["x-ticket"].GetValue<string>())
    // The differing later subject is reported, never silently dropped.
    Assert.Single accumulated.Conflicts |> ignore
    Assert.Contains("subject", accumulated.Conflicts.Head)
    Assert.Empty(Provenance.preservationViolations withSubject accumulated.Block)

    // The stored fold agrees.
    let payloads = events |> List.mapi (fun i e -> Serialization.attributedEvent Redaction.defaultRules (EventId $"E{i}") e)
    Assert.Equal(accumulated.Block, ((Store.provenanceHistory payloads |> ok)[finding.Id.Value]).Block)
