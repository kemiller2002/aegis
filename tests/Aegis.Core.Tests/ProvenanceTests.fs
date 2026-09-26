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
    Assert.Equal("a42c44e8ae0e6e16fdd513141460b700e5fa6648", source["commit"].GetValue<string>())
    let files = source["files"].AsObject()
    Assert.Equal(2, files.Count)

    for pair in files do
        use sha = SHA256.Create()
        let bytes = File.ReadAllBytes(Path.Combine(fixtureDirectory, pair.Key))
        let digest = sha.ComputeHash bytes |> Array.map (fun b -> b.ToString "x2") |> String.concat ""
        Assert.Equal(pair.Value.GetValue<string>(), digest)

[<Fact>]
let ``every vendored conformance case reaches the reference verdict and warning count`` () =
    // AEG-PROV-007, AEG-PROV-011.
    let cases = (fixture "cases.json").["cases"].AsArray()
    Assert.True(cases.Count >= 40, "expected the full conformance set")

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
    let key = ProvenanceIdentity.keyFor "op-1" at identity
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
    Assert.Equal(exeB1, ProvenanceIdentity.keyFor "op-1" at identity)

    // An agent with no declared execution is keyed by its operation.
    let noExecution = { identity with Execution = None }
    Assert.Equal("EXT-op.op-1", ProvenanceIdentity.keyFor "op/1" at noExecution)

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
    let payload = Serialization.attributedEvent Redaction.defaultRules (EventId "E2") (Provenance.attach block (FaultRecorded finding))
    Assert.Equal("aegis/event/v1", (JsonNode.Parse payload).["schema"].GetValue<string>())

    match Store.provenanceOf payload with
    | Ok(Some read) ->
        Assert.Equal(block, read)
        Assert.True(JsonNode.DeepEquals(preserved["block"], JsonNode.Parse read.Json))
    | other -> failwith $"expected the block back, got {other}"

    // The fault form carries it too, under the fault schema.
    let faultPayload = Serialization.attributedFault Redaction.defaultRules finding block
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
