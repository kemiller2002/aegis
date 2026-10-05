module Aegis.Tests.CatalogCoverage

// "Stable fault codes" is enforced, not conventional: every code Aegis
// raises has a catalog entry, and entries agree with the mappings that
// raise them (finding AEG-F12).

open System
open System.IO
open System.Text.RegularExpressions
open Xunit
open Aegis
open Aegis.Integration.GitHub

// ------------------------------------------------- characterization (red before the fix)

/// Every `FaultCode "AEGIS.*"` literal in the shipped source. Scanning the
/// source rather than a hand-kept list is the point: a new code added
/// anywhere without a catalog entry fails this test.
let private sourceCodes =
    let rec findRoot (dir: DirectoryInfo) =
        if File.Exists(Path.Combine(dir.FullName, "Aegis.sln")) then dir.FullName
        elif isNull dir.Parent then failwith "repository root not found"
        else findRoot dir.Parent

    let src = Path.Combine(findRoot (DirectoryInfo(Directory.GetCurrentDirectory())), "src")

    Directory.EnumerateFiles(src, "*.fs", SearchOption.AllDirectories)
    |> Seq.filter (fun path -> not (path.Contains $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
    |> Seq.collect (fun path ->
        Regex.Matches(File.ReadAllText path, "FaultCode\\s+\"(AEGIS\\.[A-Z0-9_.]+)\"")
        |> Seq.map (fun m -> m.Groups.[1].Value))
    |> Set.ofSeq

[<Fact>]
let ``the source scan finds the codes Aegis raises`` () =
    // Guards the scan itself: an empty or broken regex would pass vacuously.
    Assert.True(Set.count sourceCodes >= 24, $"expected at least 24 codes, found {Set.count sourceCodes}")
    Assert.Contains("AEGIS.NETWORK.TIMEOUT", sourceCodes)
    Assert.Contains("AEGIS.CONFIG.NO_SINKS", sourceCodes)

[<Fact>]
let ``every fault code Aegis raises has a catalog entry`` () =
    let missing =
        sourceCodes
        |> Set.filter (fun code -> Catalog.lookup (FaultCode code) Catalog.builtIn |> Option.isNone)

    Assert.True(Set.isEmpty missing, $"""uncatalogued fault codes: {String.Join(", ", missing)}""")
// ------------------------------------------------------------------ prevention

[<Fact>]
let ``catalog entries agree with the GitHub mapping that raises them`` () =
    let failures =
        [ GitHubFailure.AuthenticationFailed
          GitHubFailure.RepositoryNotFound "r"
          GitHubFailure.RateLimited None
          GitHubFailure.Conflict "p"
          GitHubFailure.NetworkUnavailable
          GitHubFailure.Timeout
          GitHubFailure.InvalidResponse "x" ]

    for failure in failures do
        match Catalog.lookup (GitHubFailure.code failure) Catalog.builtIn with
        | Some entry ->
            Assert.Equal(GitHubFailure.mapping.Category failure, entry.Category)
            Assert.Equal(GitHubFailure.mapping.Severity failure, entry.DefaultSeverity)
        | None -> failwith $"{failure} has no catalog entry"

[<Fact>]
let ``catalog entries agree with the bootstrap problems that raise them`` () =
    let problems =
        [ Bootstrap.MissingApplicationName
          Bootstrap.NoSinksConfigured
          Bootstrap.DuplicateSinkName "s"
          Bootstrap.RequiredSinkWithoutDurableWrite "s"
          Bootstrap.RedactionRuleWithoutName
          Bootstrap.InvalidQueueCapacity 0 ]

    for problem in problems do
        let code, _ = Bootstrap.describe problem

        match Catalog.lookup code Catalog.builtIn with
        | Some entry -> Assert.Equal(ConfigurationFailure, entry.Category)
        | None -> failwith $"{problem} has no catalog entry"

[<Fact>]
let ``every catalog entry is an Aegis code`` () =
    for KeyValue (code, entry) in Catalog.builtIn do
        Assert.StartsWith("AEGIS.", code)
        Assert.Equal(code, entry.Code.Value)
