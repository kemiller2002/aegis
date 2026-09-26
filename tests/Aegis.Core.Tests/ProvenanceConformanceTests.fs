module Aegis.Tests.ProvenanceConformance

// Runs Aegis's own provenance codec against the Praxis conformance fixtures,
// vendored under fixtures/praxis-provenance-record with their source commit
// and digests in SOURCE.json. No Praxis code is referenced.
// Requirements: AEG-PROV-003, 004, 007; RQ-ROS-2026-A013, A015.

open System
open System.IO
open System.Security.Cryptography
open System.Text.Json
open System.Text.Json.Nodes
open Xunit
open Aegis
open Aegis.Provenance

let private root = Path.Combine(AppContext.BaseDirectory, "fixtures", "praxis-provenance-record")

let private read (relative: string) = File.ReadAllText(Path.Combine(root, relative))

let private json (relative: string) = JsonNode.Parse(read relative)

let private manifest = lazy (json "manifest.json")

let private items (name: string) =
    manifest.Value[name].AsArray() |> Seq.map (fun item -> item.AsObject()) |> Seq.toList

let private text (item: JsonObject) (name: string) = item[name].GetValue<string>()

let private parsed (relative: string) =
    match Document.parse (read relative) with
    | Ok document -> document
    | Error problems -> failwith $"{relative} should parse: %A{problems}"

/// The same JSON regardless of whitespace, with key order significant.
let private canonical (text: string) = JsonNode.Parse(text).ToJsonString()

let private sha256 (path: string) =
    use stream = File.OpenRead path
    SHA256.HashData(stream) |> Array.map (fun b -> b.ToString "x2") |> String.concat ""

[<Fact>]
let ``the vendored fixtures match the digests recorded in SOURCE.json`` () =
    let source = json "SOURCE.json"
    Assert.Equal("kemiller2002/praxis", source["repository"].GetValue<string>())
    Assert.Equal("58cf46a", source["commit"].GetValue<string>())

    let recorded =
        source["files"].AsObject()
        |> Seq.map (fun pair -> pair.Key, pair.Value.GetValue<string>())
        |> Map.ofSeq

    let present =
        Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
        |> Seq.map (fun path -> Path.GetRelativePath(root, path).Replace('\\', '/'))
        |> Seq.filter (fun path -> path <> "SOURCE.json")
        |> Set.ofSeq

    Assert.Equal<Set<string>>(recorded |> Map.keys |> Set.ofSeq, present)

    for KeyValue(relative, digest) in recorded do
        Assert.True((digest = sha256 (Path.Combine(root, relative))), $"{relative} differs from Praxis {digest}")

let caseData () : obj[] seq =
    items "cases" |> Seq.map (fun item -> [| box (text item "file"); box (text item "expect") |])

[<Theory>]
[<MemberData(nameof caseData)>]
let ``every conformance case reads as the manifest expects`` (file: string) (expect: string) =
    match expect, Document.parse (read file) with
    | "valid", Ok document ->
        match document.Reading with
        | Reading.Current _ -> ()
        | other -> failwith $"{file}: expected a current record, read %A{other}"
    | "valid-unversioned", Ok document ->
        match document.Reading with
        | Reading.Unversioned _ -> ()
        | other -> failwith $"{file}: expected an unversioned record, read %A{other}"
    | "unsupported-version", Ok document ->
        match document.Reading with
        | Reading.Unsupported _ -> ()
        | other -> failwith $"{file}: expected an unsupported version, read %A{other}"
    | "invalid", Error problems -> Assert.NotEmpty problems
    | _, result -> failwith $"{file}: expected {expect}, got %A{result}"

[<Theory>]
[<MemberData(nameof caseData)>]
let ``every readable case is carried verbatim, unknown fields included`` (file: string) (_expect: string) =
    match Document.parse (read file) with
    | Ok document -> Assert.Equal(canonical (read file), document.Text)
    | Error _ -> ()

let successorData () : obj[] seq =
    items "successors"
    |> Seq.map (fun item -> [| box (text item "before"); box (text item "after"); box (text item "expect") |])

[<Theory>]
[<MemberData(nameof successorData)>]
let ``every successor pair is judged as the manifest expects`` (before: string) (after: string) (expect: string) =
    let problems = Document.successorProblemsOfText (read before) (read after)

    match expect with
    | "preserved" -> Assert.True(problems.IsEmpty, $"{after} should preserve {before}: %A{problems}")
    | "destructive" -> Assert.False(problems.IsEmpty, $"{after} should be judged destructive")
    | other -> failwith $"unknown expectation {other}"

[<Fact>]
let ``the end-to-end chain reads and every successor step is non-destructive`` () =
    let e2e = manifest.Value["e2e"]
    let steps = e2e["steps"].AsArray()

    for step in steps |> Seq.map (fun item -> item.AsObject()) do
        let file = text step "file"
        let document = parsed file

        match step["successorOf"] with
        | null -> ()
        | previous ->
            let problems = Document.successorProblems (parsed (previous.GetValue<string>())) document
            Assert.True(problems.IsEmpty, $"{file}: %A{problems}")

// ------------------------------------------- Aegis's own step: 05 -> 10

let private claudeF =
    Attribution.create (Actor.agent "anthropic/claude-code" "anthropic" "unknown" "claude-code") "EXE-20260926T150000000Z-f6f6f6f6"
    |> Result.map (Attribution.withEvidence [ "git:commit/def456" ])
    |> Result.defaultWith (fun problems -> failwith $"%A{problems}")

let private ci =
    Attribution.create Actor.githubActions "EXE-20260926T153000000Z-0a0a0a0a"
    |> Result.map (Attribution.withReason "Regression test passed")
    |> Result.defaultWith (fun problems -> failwith $"%A{problems}")

let private f17 = FaultId "F-17"
let private utc (hour: int) (minute: int) = DateTimeOffset(2026, 9, 26, hour, minute, 0, TimeSpan.Zero)

/// Aegis's own lifecycle operations: the recovery concluded by execution F
/// remediates the finding; the verified resolution is validated by CI.
let private remediateAndValidate (finding: Document) =
    finding
    |> Document.advance (Some claudeF) None (RecoveryConcluded(f17, 1, Succeeded, utc 15 0))
    |> Result.bind (
        Document.advance
            None
            (Some ci)
            (FaultResolved(
                f17,
                { Timestamp = utc 15 30
                  Kind = ResolvedManually
                  Action = None
                  Verified = true }
            ))
    )

[<Fact>]
let ``Aegis remediation and validation of the 05 finding produce exactly the 10 record`` () =
    let finding = parsed "e2e/05-aegis-finding.json"

    match remediateAndValidate finding with
    | Error problems -> failwith $"%A{problems}"
    | Ok remediated ->
        Assert.Equal(canonical (read "e2e/10-aegis-finding-remediated.json"), remediated.Text)
        Assert.Empty(Document.successorProblems finding remediated)

[<Fact>]
let ``the discoverer is unchanged after remediation and validation`` () =
    let finding = parsed "e2e/05-aegis-finding.json"

    let originator document =
        Document.record document |> Option.bind Record.originator |> Option.map (fun c -> c.Key, c.Actor)

    match remediateAndValidate finding with
    | Error problems -> failwith $"%A{problems}"
    | Ok remediated ->
        Assert.Equal(originator finding, originator remediated)
        Assert.Equal(Some("EXE-20260926T120000000Z-d4d4d4d4", Actor.agent "google/gemini-cli" "google" "gemini-2.5-pro" "gemini-cli"), originator remediated)

        let operations =
            Document.record remediated
            |> Option.map (fun record -> record.Contributions |> List.map (fun c -> c.Key, c.Operations))

        Assert.Equal(
            Some
                [ "EXE-20260926T120000000Z-d4d4d4d4", [ "created" ]
                  "EXE-20260926T150000000Z-f6f6f6f6", [ "x-remediated" ]
                  "EXE-20260926T153000000Z-0a0a0a0a", [ "x-validated" ] ],
            operations
        )

[<Fact>]
let ``the 05 finding is what Aegis writes when agent D discovers it`` () =
    // Discovery: the discovering agent is the single `created` contribution;
    // the affected artifacts are lineage, their records carried verbatim.
    let finding = parsed "e2e/05-aegis-finding.json"

    let sources =
        let parsedFinding = JsonNode.Parse finding.Text
        parsedFinding["sources"].AsObject()
        |> Seq.map (fun pair ->
            match Document.parse (pair.Value.ToJsonString()) with
            | Ok document -> pair.Key, document
            | Error problems -> failwith $"%A{problems}")
        |> Seq.toList

    let geminiD =
        Attribution.create (Actor.agent "google/gemini-cli" "google" "gemini-2.5-pro" "gemini-cli") "EXE-20260926T120000000Z-d4d4d4d4"
        |> Result.map (Attribution.withReason "Security review" >> Attribution.withEvidence [ "dokimos:snapshot/app:abc123" ])
        |> Result.defaultWith (fun problems -> failwith $"%A{problems}")

    match Document.discovered (Document.subjectOf f17) (utc 12 0) geminiD [] sources with
    | Error problems -> failwith $"%A{problems}"
    | Ok written -> Assert.Equal(finding.Text, written.Text)

[<Fact>]
let ``the remediated finding travels on a lifecycle event verbatim`` () =
    let finding = parsed "e2e/10-aegis-finding-remediated.json"

    let options =
        { Serialization.noOptions with
            ValidatedBy = Some ci
            Provenance = Some finding }

    let resolved =
        FaultResolved(
            f17,
            { Timestamp = utc 15 30
              Kind = ResolvedManually
              Action = None
              Verified = true }
        )

    match Serialization.eventWith Redaction.defaultRules options (EventId "01E9") resolved with
    | Error problems -> failwith $"%A{problems}"
    | Ok payload ->
        match Store.provenance payload with
        | Ok(Some carried) -> Assert.Equal(finding.Text, carried.Text)
        | other -> failwith $"%A{other}"
