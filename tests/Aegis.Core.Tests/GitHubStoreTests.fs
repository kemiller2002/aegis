module Aegis.Tests.GitHubStore

open System
open Xunit
open Aegis
open Aegis.Store.GitHub
open Aegis.Store.GitHub.GitHubStore

let private at = DateTimeOffset(2026, 9, 7, 5, 4, 3, TimeSpan.Zero)

/// An in-memory stand-in for the repository operations the integration
/// assembly supplies. No network, no mocking framework: the contract is a
/// record of functions, so a fake is just a value.
type private Fake() =
    let files = System.Collections.Generic.Dictionary<string, string>()
    let commits = ResizeArray<string list>()
    member val ExistsFails = false with get, set
    member val PutFails = false with get, set
    member val ListFails = false with get, set
    /// Commits succeed until this many have been made, then fail: a batch
    /// that half-applies. Requirement: logging 37.
    member val CommitLimit = Int32.MaxValue with get, set
    member _.Files = files
    member _.Commits = commits |> List.ofSeq
    member _.Seed(path, content) = files.[path] <- content

    member this.Operations =
        { Exists =
            fun path ->
                async { return if this.ExistsFails then Result.Error "github unreachable" else Ok(files.ContainsKey path) }
          PutFile =
            fun path content _ ->
                async {
                    if this.PutFails || commits.Count >= this.CommitLimit then
                        return Result.Error "github write rejected"
                    else
                        files.[path] <- content
                        commits.Add [ path ]
                        return Ok()
                }
          PutFiles =
            fun entries _ ->
                async {
                    if this.PutFails || commits.Count >= this.CommitLimit then
                        return Result.Error "github write rejected"
                    else
                        for path, content in entries do
                            files.[path] <- content
                        commits.Add(entries |> List.map fst)
                        return Ok()
                }
          ListPrefix =
            fun prefix ->
                async {
                    return
                        if this.ListFails then
                            Result.Error "github unreachable"
                        else
                            files
                            |> Seq.filter (fun kv -> kv.Key.StartsWith prefix)
                            |> Seq.map (fun kv -> kv.Key, kv.Value)
                            |> List.ofSeq
                            |> Ok
                } }

let private config =
    { defaults "kemiller2002" "aegis" with Now = fun () -> at }

let private payloadFor (eventId: string) (faultId: string) (code: string) (timestamp: DateTimeOffset) =
    let fault =
        { Id = FaultId faultId
          CorrelationId = CorrelationId "CORR1"
          Timestamp = timestamp
          Application = "Chrona"
          ApplicationVersion = None
          Operation = "Chrona.TimeEntry.Load"
          Category = IntegrationFailure
          Code = FaultCode code
          Severity = FaultSeverity.Warning
          Impact = OperationOnly
          Domain = IntegrationDomain
          Radius = OneOperation
          Retention = DiagnosticOnly
          Persistence = Transient
          Owner = None
          Dependencies = [ "Chrona"; "GitHubIntegration" ]
          UserMessage = "Unable to load time entries."
          TechnicalDetails = None
          Context = Map.empty
          Recovery = NoRecovery
          Diagnostics = noDiagnostics
          Cause = None }

    Serialization.event Redaction.defaultRules (EventId eventId) (FaultRecorded fault)

// ------------------------------------------------------------------ path layout

[<Fact>]
let ``events are stored one immutable file per event in date buckets`` () =
    // Requirement: logging 7.
    Assert.Equal("aegis/2026/09/07/01ABC.json", pathFor config at (EventId "01ABC"))

[<Fact>]
let ``path components are zero padded so lexical order matches chronological`` () =
    let january = DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero)
    Assert.Equal("aegis/2026/01/02/01X.json", pathFor config january (EventId "01X"))

[<Fact>]
let ``file name is the event id alone and carries no message text`` () =
    // Requirement: logging 8 -- names must not depend on mutable messages.
    let path = pathFor config at (EventId "01SORTABLE")
    Assert.EndsWith("01SORTABLE.json", path)
    Assert.DoesNotContain("Unable to load", path)

[<Fact>]
let ``a deferred event is bucketed by when it happened not when it was flushed`` () =
    // Requirement: logging 20.
    let happened = DateTimeOffset(2026, 3, 4, 1, 2, 3, TimeSpan.Zero)
    let payload = payloadFor "01DEFERRED" "F1" "CHRONA.GITHUB.LOAD_FAILED" happened
    Assert.Equal("aegis/2026/03/04/01DEFERRED.json", pathForPayload config (EventId "01DEFERRED") payload)

[<Fact>]
let ``root path is configurable`` () =
    // Requirement: logging 9.
    let custom = { config with RootPath = "diagnostics/aegis" }
    Assert.StartsWith("diagnostics/aegis/", pathFor custom at (EventId "01X"))

// ----------------------------------------------------------------------- append

[<Fact>]
let ``append writes the event once at its computed path`` () =
    let fake = Fake()
    let store = create config fake.Operations
    let payload = payloadFor "01A" "F1" "CHRONA.GITHUB.LOAD_FAILED" at

    let result = store.Append (EventId "01A") payload |> Async.RunSynchronously

    Assert.Equal(Ok(), result)
    Assert.Equal(payload, fake.Files.["aegis/2026/09/07/01A.json"])
    Assert.Single fake.Commits |> ignore

[<Fact>]
let ``append never silently overwrites an existing event file`` () =
    // Requirement: logging 36 -- a collision is abnormal, not an overwrite cue.
    let fake = Fake()
    fake.Seed("aegis/2026/09/07/01A.json", "{\"original\":true}")
    let store = create config fake.Operations

    let result =
        store.Append (EventId "01A") (payloadFor "01A" "F1" "CHRONA.GITHUB.LOAD_FAILED" at)
        |> Async.RunSynchronously

    Assert.Equal(Result.Error(Store.Conflict "aegis/2026/09/07/01A.json"), result)
    // The original content survives and no commit was made.
    Assert.Equal("{\"original\":true}", fake.Files.["aegis/2026/09/07/01A.json"])
    Assert.Empty fake.Commits

[<Fact>]
let ``an unreachable repository is reported as unavailable not as a conflict`` () =
    let fake = Fake(ExistsFails = true)
    let store = create config fake.Operations

    match store.Append (EventId "01A") (payloadFor "01A" "F1" "C" at) |> Async.RunSynchronously with
    | Result.Error (Store.Unavailable reason) -> Assert.Equal("github unreachable", reason)
    | other -> failwith $"expected Unavailable, got {other}"

[<Fact>]
let ``a rejected write is reported rather than swallowed`` () =
    let fake = Fake(PutFails = true)
    let store = create config fake.Operations

    match store.Append (EventId "01A") (payloadFor "01A" "F1" "C" at) |> Async.RunSynchronously with
    | Result.Error (Store.Unavailable _) -> ()
    | other -> failwith $"expected a failure, got {other}"

// ------------------------------------------------------------ commit strategies

[<Fact>]
let ``one commit per event is the default strategy`` () =
    // Requirement: logging 35.
    let fake = Fake()
    let store = create config fake.Operations

    let items = [ for n in 1..3 -> EventId $"01E{n}", payloadFor $"01E{n}" "F1" "C" at ]
    Assert.Equal(Ok(), store.AppendBatch items |> Async.RunSynchronously)
    Assert.Equal(3, List.length fake.Commits)

[<Fact>]
let ``batching groups events into fewer commits without losing any`` () =
    // Requirements: logging 19, 35 -- batching must not lose identity.
    let fake = Fake()
    let store = create { config with CommitStrategy = Batched 2 } fake.Operations

    let items = [ for n in 1..5 -> EventId $"01E{n}", payloadFor $"01E{n}" "F1" "C" at ]
    Assert.Equal(Ok(), store.AppendBatch items |> Async.RunSynchronously)
    Assert.Equal(3, List.length fake.Commits) // 2 + 2 + 1
    Assert.Equal(5, fake.Files.Count)

[<Fact>]
let ``a batch containing a conflict commits nothing`` () =
    // Silent partial persistence is not acceptable (logging 37 applied here).
    let fake = Fake()
    fake.Seed("aegis/2026/09/07/01E2.json", "{\"original\":true}")
    let store = create { config with CommitStrategy = Batched 5 } fake.Operations

    let items = [ for n in 1..3 -> EventId $"01E{n}", payloadFor $"01E{n}" "F1" "C" at ]

    match store.AppendBatch items |> Async.RunSynchronously with
    | Result.Error (Store.Conflict path) -> Assert.Equal("aegis/2026/09/07/01E2.json", path)
    | other -> failwith $"expected a conflict, got {other}"

    Assert.Empty fake.Commits
    Assert.Equal("{\"original\":true}", fake.Files.["aegis/2026/09/07/01E2.json"])

// ------------------------------------------------------------------ query model

let private seeded () =
    let fake = Fake()
    let store = create config fake.Operations

    [ EventId "01A", payloadFor "01A" "F1" "CHRONA.GITHUB.LOAD_FAILED" at
      EventId "01B", payloadFor "01B" "F1" "CHRONA.GITHUB.LOAD_FAILED" (at.AddHours 1.)
      EventId "01C", payloadFor "01C" "F2" "CHRONA.GITHUB.SAVE_FAILED" (at.AddDays 2.) ]
    |> store.AppendBatch
    |> Async.RunSynchronously
    |> ignore

    fake, store

[<Fact>]
let ``query by fault id returns only that fault's events`` () =
    // Requirements: logging 23, 27.
    let _, store = seeded ()

    match store.Query { Store.anyEvent with FaultId = Some(FaultId "F1") } |> Async.RunSynchronously with
    | Ok results -> Assert.Equal(2, List.length results)
    | other -> failwith $"unexpected {other}"

[<Fact>]
let ``query by code and by time range narrow independently`` () =
    let _, store = seeded ()

    let byCode =
        store.Query { Store.anyEvent with Code = Some(FaultCode "CHRONA.GITHUB.SAVE_FAILED") }
        |> Async.RunSynchronously

    match byCode with
    | Ok results -> Assert.Single results |> ignore
    | other -> failwith $"unexpected {other}"

    let byRange =
        store.Query { Store.anyEvent with From = Some(at.AddDays 1.) } |> Async.RunSynchronously

    match byRange with
    | Ok results -> Assert.Single results |> ignore
    | other -> failwith $"unexpected {other}"

[<Fact>]
let ``query results come back in stored order`` () =
    // Requirement: logging 33 -- date-bucketed sortable paths give ordering.
    let _, store = seeded ()

    match store.Query Store.anyEvent |> Async.RunSynchronously with
    | Ok results ->
        Assert.Equal(3, List.length results)
        Assert.Contains("\"eventId\":\"01A\"", List.head results)
    | other -> failwith $"unexpected {other}"

[<Fact>]
let ``a malformed stored record fails the query explicitly instead of being skipped`` () =
    // Requirement: logging 40 -- malformed storage responses. Partial
    // failure is not success (aegis#13 AEGIS-QUAL-002): a query that could
    // not read every record must not answer as though it had. This test
    // previously asserted `Ok` with the broken record silently dropped,
    // which made "no events" indistinguishable from "events unreadable".
    let fake, store = seeded ()
    fake.Seed("aegis/2026/09/07/broken.json", "{ this is not json")

    match store.Query Store.anyEvent |> Async.RunSynchronously with
    | Result.Error (Store.Malformed detail) -> Assert.Contains("aegis/2026/09/07/broken.json", detail)
    | other -> failwith $"expected Malformed naming the unreadable record, got {other}"

[<Fact>]
let ``an unavailable repository fails the query explicitly`` () =
    let fake, store = seeded ()
    fake.ListFails <- true

    match store.Query Store.anyEvent |> Async.RunSynchronously with
    | Result.Error (Store.Unavailable _) -> ()
    | other -> failwith $"expected Unavailable, got {other}"

// -------------------------------------------------------------- index + matches

[<Fact>]
let ``indexing recovers the searchable fields from a payload`` () =
    // Requirement: additional 41 -- structured fields, not text search.
    match Store.index (payloadFor "01A" "F1" "CHRONA.GITHUB.LOAD_FAILED" at) with
    | Ok indexed ->
        Assert.Equal(EventId "01A", indexed.EventId)
        Assert.Equal(Some(FaultId "F1"), indexed.FaultId)
        Assert.Equal(Some(FaultCode "CHRONA.GITHUB.LOAD_FAILED"), indexed.Code)
        Assert.Equal("FaultRecorded", indexed.EventType)
        Assert.Equal(Some at, indexed.Timestamp)
    | Result.Error e -> failwith $"expected an index, got {e}"

[<Fact>]
let ``indexing a non-event payload reports malformed`` () =
    match Store.index "{\"unrelated\":true}" with
    | Result.Error (Store.Malformed _) -> ()
    | other -> failwith $"expected Malformed, got {other}"

[<Fact>]
let ``the empty query matches every event`` () =
    match Store.index (payloadFor "01A" "F1" "C" at) with
    | Ok indexed -> Assert.True(Store.matches Store.anyEvent indexed)
    | Result.Error e -> failwith $"{e}"

[<Fact>]
let ``a query on a field the event lacks does not match`` () =
    match Store.index (payloadFor "01A" "F1" "C" at) with
    | Ok indexed ->
        Assert.False(Store.matches { Store.anyEvent with Operation = Some "Other.Operation" } indexed)
        Assert.False(Store.matches { Store.anyEvent with EventType = Some "FaultResolved" } indexed)
    | Result.Error e -> failwith $"{e}"

// ------------------------------------------------- idempotent replay (logging 32)

[<Fact>]
let ``the sink stores an event under the event id inside its payload`` () =
    // The payload already carries its eventId; minting a second id for the
    // file name made every retry of the same event a new file.
    let fake = Fake()
    let store = create config fake.Operations
    let queue = ref (Offline.create 10)
    let sink = sink store Sinks.Required queue (fun () -> EventId "MINTED")

    sink.Write(payloadFor "01PAYLOAD" "F1" "C" at) |> Async.RunSynchronously

    Assert.True(fake.Files.ContainsKey "aegis/2026/09/07/01PAYLOAD.json")
    Assert.False(fake.Files.ContainsKey "aegis/2026/09/07/MINTED.json")

[<Fact>]
let ``replaying a half-committed batch completes it without duplicates or conflicts`` () =
    let fake = Fake(CommitLimit = 1)
    let store = create { config with CommitStrategy = Batched 2 } fake.Operations
    let items = [ for n in 1..4 -> EventId $"01E{n}", payloadFor $"01E{n}" "F1" "C" at ]

    // The first chunk commits, the second fails.
    match store.AppendBatch items |> Async.RunSynchronously with
    | Result.Error (Store.Unavailable _) -> ()
    | other -> failwith $"expected the half-applied batch to fail, got {other}"

    Assert.Equal(2, fake.Files.Count)

    // The same batch, replayed once the outage clears.
    fake.CommitLimit <- Int32.MaxValue
    Assert.Equal(Ok(), store.AppendBatch items |> Async.RunSynchronously)
    Assert.Equal(4, fake.Files.Count)
    // Only the uncommitted chunk was written on replay.
    Assert.Equal(2, List.length fake.Commits)

[<Fact>]
let ``a replayed event with identical content is idempotent, a different one is a conflict`` () =
    let fake = Fake()
    let store = create config fake.Operations
    let payload = payloadFor "01A" "F1" "C" at

    Assert.Equal(Ok(), store.Append (EventId "01A") payload |> Async.RunSynchronously)
    Assert.Equal(Ok(), store.Append (EventId "01A") payload |> Async.RunSynchronously)
    Assert.Single fake.Commits |> ignore

    match store.Append (EventId "01A") (payloadFor "01A" "F2" "OTHER" at) |> Async.RunSynchronously with
    | Result.Error (Store.Conflict _) -> ()
    | other -> failwith $"expected a conflict for different content, got {other}"

[<Fact>]
let ``a deferred batch is queued under the payload ids so its replay is idempotent`` () =
    let fake = Fake(CommitLimit = 1)
    let store = create { config with CommitStrategy = Batched 1 } fake.Operations
    let queue = ref (Offline.create 10)
    let minted = ref 0

    let sink =
        sink store Sinks.Required queue (fun () ->
            minted.Value <- minted.Value + 1
            EventId $"MINTED{minted.Value}")

    let payloads = [ payloadFor "01E1" "F1" "C" at; payloadFor "01E2" "F1" "C" at ]

    let failed =
        try
            sink.WriteBatch.Value payloads |> Async.RunSynchronously
            false
        with _ ->
            true

    Assert.True(failed, "a deferred batch must still report that it did not persist")
    Assert.Equal<EventId list>([ EventId "01E1"; EventId "01E2" ], Offline.pendingIds queue.Value)

    // Drain through the sink once the outage clears: nothing conflicts and
    // nothing is written twice.
    fake.CommitLimit <- Int32.MaxValue
    let drained = Offline.drainAsync sink.Write queue.Value |> Async.RunSynchronously
    Assert.Equal(None, drained.Failed)
    Assert.Equal(2, fake.Files.Count)
    Assert.Equal(0, minted.Value)

[<Fact>]
let ``queryDetailed returns the readable records and lists the unreadable ones`` () =
    let fake, _ = seeded ()
    fake.Seed("aegis/2026/09/07/broken.json", "{ this is not json")

    match queryDetailed config fake.Operations Store.anyEvent |> Async.RunSynchronously with
    | Ok outcome ->
        Assert.Equal(3, List.length outcome.Matched)
        Assert.Equal<string list>([ "aegis/2026/09/07/broken.json" ], outcome.Unreadable |> List.map (fun u -> u.Path))
    | other -> failwith $"unexpected {other}"

[<Fact>]
let ``a complete query outcome is success and an incomplete one is not`` () =
    Assert.Equal(Ok [ "a" ], Store.complete { Store.Matched = [ "a" ]; Store.Unreadable = [] })

    match Store.complete { Store.Matched = [ "a" ]; Store.Unreadable = [ { Store.Path = "p"; Store.Reason = "r" } ] } with
    | Result.Error (Store.Malformed detail) -> Assert.Contains("p (r)", detail)
    | other -> failwith $"expected Malformed, got {other}"
