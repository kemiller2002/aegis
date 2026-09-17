module Aegis.Tests.Boundaries

open System
open System.IO
open System.Text.Json
open Xunit
open Aegis

/// The declaration is only worth having if it cannot quietly drift from the
/// code, so these tests check it against what actually exists.
/// Requirements: core 33; logging 46.

let private declarationPath =
    let rec find (dir: DirectoryInfo) =
        let candidate = Path.Combine(dir.FullName, "aegis-boundaries.json")
        if File.Exists candidate then candidate
        elif isNull dir.Parent then failwith "aegis-boundaries.json not found"
        else find dir.Parent

    find (DirectoryInfo(Directory.GetCurrentDirectory()))

let private declaration = JsonDocument.Parse(File.ReadAllText declarationPath)

let private boundaries =
    declaration.RootElement.GetProperty("boundaries").EnumerateArray() |> List.ofSeq

let private codesOf (boundary: JsonElement) =
    boundary.GetProperty("codes").EnumerateArray()
    |> Seq.map (fun c -> c.GetString())
    |> List.ofSeq

[<Fact>]
let ``the declaration is well formed`` () =
    Assert.Equal("aegis/boundaries/v1", declaration.RootElement.GetProperty("schema").GetString())
    Assert.NotEmpty boundaries

    for boundary in boundaries do
        for field in [ "name"; "kind"; "owner" ] do
            Assert.False(String.IsNullOrWhiteSpace(boundary.GetProperty(field).GetString()), $"{field} is empty")

        Assert.NotEmpty(codesOf boundary)

[<Fact>]
let ``every declared boundary names the kinds core 6 lists`` () =
    // Requirement: core 6 -- boundaries are where Aegis belongs.
    let recognised =
        set
            [ "persistent-storage"; "external-service"; "serialization"; "data-integrity"
              "migration"; "startup"; "shutdown"; "sink"; "ui-interop"; "top-level" ]

    for boundary in boundaries do
        let kind = boundary.GetProperty("kind").GetString()
        Assert.True(recognised.Contains kind, $"unrecognised boundary kind: {kind}")

[<Fact>]
let ``declared fault codes follow the stable code format`` () =
    // Requirement: core 4.
    for boundary in boundaries do
        for code in codesOf boundary do
            Assert.StartsWith("AEGIS.", code)
            Assert.Equal(code, code.ToUpperInvariant())
            Assert.DoesNotContain(" ", code)

[<Fact>]
let ``declared codes are unique across boundaries`` () =
    let all = boundaries |> List.collect codesOf
    Assert.Equal(List.length all, all |> List.distinct |> List.length)

[<Fact>]
let ``a boundary marked guarded has an owning assembly that exists`` () =
    // Requirement: core 33 -- the point is to surface unguarded boundaries.
    let assemblies = set [ "Aegis.Core"; "Aegis.Store.GitHub"; "Aegis.Integration.GitHub" ]

    for boundary in boundaries do
        if boundary.GetProperty("guarded").GetBoolean() then
            let owner = boundary.GetProperty("owner").GetString()
            Assert.True(assemblies.Contains owner, $"guarded boundary owned by unknown assembly: {owner}")

[<Fact>]
let ``an unguarded boundary is declared as such rather than omitted`` () =
    // Recording the gap is the whole value: a boundary that exists in the
    // design but not the code must stay visible.
    let unguarded =
        boundaries |> List.filter (fun b -> not (b.GetProperty("guarded").GetBoolean()))

    // Limen interop is known to be unimplemented here.
    Assert.Contains("Limen interop", unguarded |> List.map (fun b -> b.GetProperty("name").GetString()))

[<Fact>]
let ``codes the catalog knows about are declared on some boundary`` () =
    // Keeps the declaration honest as the catalog grows.
    let declared = boundaries |> List.collect codesOf |> Set.ofList

    let missing =
        Catalog.builtIn
        |> Map.toList
        |> List.map fst
        |> List.filter (fun code -> not (declared.Contains code))

    Assert.True(List.isEmpty missing, $"catalog codes not declared on any boundary: {missing}")

[<Fact>]
let ``configuration codes match what the code actually raises`` () =
    // The declaration must track Bootstrap.describe rather than drift from it.
    let declared =
        boundaries
        |> List.filter (fun b -> b.GetProperty("kind").GetString() = "startup")
        |> List.collect codesOf
        |> Set.ofList

    let actual =
        [ Bootstrap.MissingApplicationName
          Bootstrap.NoSinksConfigured
          Bootstrap.DuplicateSinkName "x"
          Bootstrap.RequiredSinkWithoutDurableWrite "x"
          Bootstrap.RedactionRuleWithoutName
          Bootstrap.InvalidQueueCapacity 0 ]
        |> List.map (fun p -> (Bootstrap.describe p |> fst).Value)
        |> Set.ofList

    Assert.Equal<Set<string>>(actual, declared)

[<Fact>]
let ``integrity and migration codes match what the code actually raises`` () =
    let declared =
        boundaries
        |> List.filter (fun b -> [ "data-integrity"; "migration" ] |> List.contains (b.GetProperty("kind").GetString()))
        |> List.collect codesOf
        |> Set.ofList

    let actual =
        [ Integrity.InvalidPersistedState "d"
          Integrity.MissingRequiredRelationship "d"
          Integrity.HashMismatch("a", "b")
          Integrity.UnexpectedRepositoryStructure "d"
          Integrity.Migration(Integrity.MigrationRequired("v1", "v2"))
          Integrity.Migration(Integrity.MigrationFailed "d")
          Integrity.Migration(Integrity.UnsupportedVersion "v9")
          Integrity.Migration(Integrity.SchemaMismatch "d")
          Integrity.Migration(Integrity.ForwardVersionUnsupported "v9")
          Integrity.Migration(Integrity.BackwardCompatibilityViolation "d") ]
        |> List.map (fun f -> (Integrity.code f).Value)
        |> Set.ofList

    // Every code the integrity taxonomy can raise is declared. The declaration
    // may also list codes raised elsewhere, such as deserialization.
    Assert.Empty(Set.difference actual declared)
