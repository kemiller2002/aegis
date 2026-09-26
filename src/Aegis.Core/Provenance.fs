namespace Aegis

open System
open System.Collections.Generic
open System.Globalization
open System.Security.Cryptography
open System.Text
open System.Text.Encodings.Web
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions

// Contribution provenance for faults and security findings.
//
// Aegis does not define an identity model. It carries the Praxis interchange
// block `praxis.provenance/1` (Praxis DF-ROS-2026-A037, RQ-ROS-2026-A013..A019)
// and applies the same receiving and appending rules as Praxis's reference
// library (`lib/provenance-interchange.mjs`), so every Echelon system reaches
// the same verdict on the same block. The conformance fixtures are vendored
// in tests/fixtures/praxis-provenance/.
// Requirements: AEG-PROV-001..AEG-PROV-012; decision DF-AEGIS-2026-DC5B.

/// A Praxis actor: who or what acted. `Kind` is agent, human, automation,
/// unknown, or an `x-...` extension. Non-human actors carry Provider, Model
/// and Runtime (the literal "unknown" when not known); humans omit them.
/// This is self-reported provenance, not authentication, authorization or
/// evidence weight. Requirement: AEG-PROV-002, AEG-PROV-010.
type ProvenanceActor =
    { Kind: string
      Id: string
      Provider: string option
      Model: string option
      Runtime: string option }

/// One contribution to record: an execution (or contributor) key, the actor,
/// when, and the operations it performed. Requirements: AEG-PROV-002, AEG-PROV-003.
type ProvenanceContribution =
    { /// EXE-... (Praxis execution), EXT-<system>.<run-id> (another Echelon
      /// system's execution), or CTB-... (a non-agent outside any execution).
      Key: string
      Actor: ProvenanceActor
      At: DateTimeOffset
      /// created, discovered, remediated, validated, reviewed, modified, ...
      Operations: string list
      Reason: string option
      /// References to supporting evidence, never the evidence itself.
      Evidence: string list }

/// A contribution as recorded in a block. `At` and `Last` are kept as the
/// exact timestamp strings the block carries.
type RecordedContribution =
    { Key: string
      Actor: ProvenanceActor
      At: string
      Last: string option
      Operations: string list
      Reason: string option
      Evidence: string list }

/// How a received block may be treated. Requirement: AEG-PROV-007.
[<RequireQualifiedAccess>]
type ProvenanceVerdict =
    /// Understood. Warnings name tolerated forward-compatible content.
    | Supported of warnings: string list
    /// Another major version: carry verbatim, never interpret or merge.
    | Unsupported of schema: string
    /// Reject at the boundary; never drop or repair.
    | Malformed of problems: string list

/// A provenance block that passed the boundary: supported or unsupported,
/// never malformed, because the only ways to obtain one are classifying JSON
/// or appending through the codec. Its JSON is kept verbatim (compacted), so
/// fields Aegis does not model survive. Requirement: AEG-PROV-007.
[<CustomEquality; NoComparison>]
type ProvenanceBlock =
    private
        { text: string
          schema: string
          supported: bool }

    /// The block's JSON, carried verbatim.
    member this.Json = this.text
    /// The block's schema tag (`praxis.provenance/1` when it carries none).
    member this.Schema = this.schema
    /// False for another major version, which Aegis carries but never reads.
    member this.IsSupported = this.supported
    override this.ToString() = this.text

    override this.Equals(other) =
        match other with
        | :? ProvenanceBlock as block ->
            this.text = block.text
            || (try
                    JsonNode.DeepEquals(JsonNode.Parse this.text, JsonNode.Parse block.text)
                with _ ->
                    false)
        | _ -> false

    override this.GetHashCode() = this.schema.GetHashCode()

/// An Aegis event with the contribution provenance of the act it records.
/// The event itself is unchanged, so every existing consumer keeps working;
/// the block is written under the serialized event's `provenance` field.
/// Requirements: AEG-PROV-001, AEG-PROV-003, AEG-PROV-012.
type AttributedEvent =
    { Event: AegisEvent
      Provenance: ProvenanceBlock option }

/// One fault's accumulated contribution provenance, folded from its event
/// stream. Requirement: AEG-PROV-004, AEG-PROV-008.
type FaultProvenance =
    { FaultId: FaultId
      /// The accumulated `praxis.provenance/1` block (no contributions when
      /// nothing was attributed).
      Block: ProvenanceBlock
      /// False when no event for this fault carried provenance: a legacy or
      /// unattributed fault. Nothing is inferred.
      Attributed: bool
      /// Blocks of another major version, carried verbatim and never merged.
      Carried: ProvenanceBlock list
      /// Contributions the fold refused (re-attribution, a late or second
      /// `created`), reported rather than silently dropped.
      Conflicts: string list
      /// Events whose provenance was rejected when written (stored as
      /// `provenanceRejected`), with the recorded reason: never mistaken for
      /// a legacy or unattributed event. Requirement: AEG-PROV-008.
      Rejected: string list }

/// What a stored event says about its contribution provenance.
/// Requirements: AEG-PROV-007, AEG-PROV-008.
[<RequireQualifiedAccess>]
type StoredProvenance =
    /// No provenance field: a legacy or genuinely unattributed event.
    | Absent
    /// A block that passed the boundary on read (supported or unsupported).
    | Carried of ProvenanceBlock
    /// The writer refused the block (it matched a redaction rule) and
    /// recorded `provenanceRejected` with this reason instead.
    | Rejected of reason: string

/// The `praxis.provenance/1` codec: classify, append, add lineage, check
/// preservation, and read roles. Pure: inputs are never mutated.
[<RequireQualifiedAccess>]
module Provenance =

    [<Literal>]
    let SchemaTag = "praxis.provenance/1"

    let private schemaPattern = Regex("^praxis\\.provenance/([1-9][0-9]*)\\z", RegexOptions.CultureInvariant)
    let private executionKey = Regex("^EXE-[A-Za-z0-9._-]+\\z", RegexOptions.CultureInvariant)
    let private contributionKey = Regex("^CTB-[A-Za-z0-9._-]+\\z", RegexOptions.CultureInvariant)
    let private foreignKey = Regex("^EXT-([a-z][a-z0-9-]*)\\.([A-Za-z0-9._-]+)\\z", RegexOptions.CultureInvariant)
    let private kindPattern = Regex("^(agent|human|automation|unknown|x-[a-z0-9][a-z0-9-]*)\\z", RegexOptions.CultureInvariant)
    let private operationGrammar = Regex("^[a-z][a-z0-9-]*\\z", RegexOptions.CultureInvariant)
    let private extension = Regex("^x-[a-z0-9][a-z0-9-]*\\z", RegexOptions.CultureInvariant)

    // Contract 1.1: every pattern is anchored with \z, because .NET's `$`
    // also matches before a trailing newline ("human\n" must be malformed).
    let private timestampPattern =
        Regex(
            "^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,9}))?Z\\z",
            RegexOptions.CultureInvariant
        )

    [<Literal>]
    let private Unknown = "unknown"

    /// Operations this version knows. Anything else matching the grammar is
    /// tolerated, preserved and reported.
    let knownOperations =
        [ "created"; "modified"; "reviewed"; "approved"; "superseded"; "migrated"
          "discovered"; "measured"; "transformed"; "remediated"; "validated"; "resolved" ]

    /// Recognisable credential shapes. A tripwire for accidents, not a secret
    /// scanner. Requirement: AEG-PROV-007 (Praxis RQ-ROS-2026-A017).
    let private credentialPatterns =
        [ "gh[pousr]_[A-Za-z0-9]{20,}"
          "github_pat_[A-Za-z0-9_]{20,}"
          "sk-[A-Za-z0-9_-]{20,}"
          "AKIA[0-9A-Z]{16}"
          "xox[abprs]-[A-Za-z0-9-]{10,}"
          "-----BEGIN [A-Z ]*PRIVATE KEY-----"
          // Contract 1.2: ASCII-only semantics -- no word boundary, \\s class or case folding,
          // whose meaning differs between .NET, JavaScript and Python.
          "(?:^|[^A-Za-z0-9_])[Bb][Ee][Aa][Rr][Ee][Rr][\\t\\n\\v\\f\\r ]+[A-Za-z0-9._~+/=-]{16,}"
          "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\." ]
        |> List.map (fun pattern -> Regex(pattern, RegexOptions.CultureInvariant))

    let isCredentialLike (value: string) =
        credentialPatterns |> List.exists (fun pattern -> pattern.IsMatch value)

    /// Contract 1.2: whitespace is ASCII only (tab, LF, VT, FF, CR, space).
    /// U+0085, U+FEFF, U+001C, U+00A0 and every other character are content.
    let private asciiWhitespace = [| '\t'; '\n'; '\011'; '\012'; '\r'; ' ' |]

    let asciiTrim (value: string) = value.Trim asciiWhitespace

    /// Empty after trimming ASCII whitespace only.
    let isBlank (value: string) = isNull value || (asciiTrim value).Length = 0

    let private strictUtf8 = UTF8Encoding(false, true)

    /// Contract 1.2: well-formed Unicode, i.e. no unpaired UTF-16 surrogate
    /// (which has no UTF-8 form and cannot be carried verbatim).
    let isWellFormed (value: string) =
        not (isNull value)
        && (try
                strictUtf8.GetByteCount value |> ignore
                true
            with :? EncoderFallbackException ->
                false)

    // ------------------------------------------------------------ JSON helpers

    let private writeOptions =
        JsonSerializerOptions(Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, WriteIndented = false)

    let private compact (node: JsonNode) = node.ToJsonString writeOptions

    let private asString (node: JsonNode) =
        match node with
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.String -> Some(value.GetValue<string>())
        | _ -> None

    let private isNonEmpty (node: JsonNode) =
        asString node |> Option.exists (isBlank >> not)

    let private present (o: JsonObject) (name: string) = o.ContainsKey name

    let private field (o: JsonObject) (name: string) =
        match o.TryGetPropertyValue name with
        | true, value -> value
        | _ -> null

    /// Milliseconds since 0001-01-01 for a calendar-valid UTC timestamp
    /// (year 0001-9999, no Feb 30, no 24:00), or None. Ordering is at
    /// millisecond precision: extra fraction digits are truncated, never
    /// rounded (contract 1.1). Never throws.
    let private instant (value: string) =
        let m = timestampPattern.Match value

        if not m.Success then
            None
        else
            let number (group: int) = Int32.Parse(m.Groups[group].Value, CultureInfo.InvariantCulture)
            let year, month, day = number 1, number 2, number 3
            let hour, minute, second = number 4, number 5, number 6
            let fraction = m.Groups[7].Value.PadRight(3, '0').Substring(0, 3)

            if year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59 then None
            elif day < 1 || day > DateTime.DaysInMonth(year, month) then None
            else
                let date = DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc)
                Some(date.Ticks / TimeSpan.TicksPerMillisecond + int64 (Int32.Parse(fraction, CultureInfo.InvariantCulture)))

    let private order (value: string) =
        instant value |> Option.defaultValue Int64.MaxValue

    let private isKnown (value: string option) =
        value |> Option.exists (fun text -> not (isBlank text) && asciiTrim text <> Unknown)

    /// UTC, millisecond precision, `Z` suffix: the same canonical form as
    /// every other Aegis timestamp (AEG-LOG-025).
    let timestamp (t: DateTimeOffset) =
        t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture)

    /// Dotted paths of every key or string value that looks like a credential.
    let credentialFindings (node: JsonNode) =
        let rec walk (path: string) (current: JsonNode) : string list =
            match current with
            | :? JsonObject as item ->
                item
                |> Seq.toList
                |> List.collect (fun pair ->
                    let child = if path.Length = 0 then pair.Key else $"{path}.{pair.Key}"
                    (if isCredentialLike pair.Key then [ child ] else []) @ walk child pair.Value)
            | :? JsonArray as items -> items |> Seq.toList |> List.mapi (fun i value -> walk $"{path}[{i}]" value) |> List.concat
            | _ ->
                match asString current with
                | Some text when isCredentialLike text -> [ path ]
                | _ -> []

        walk "" node

    /// Dotted paths of every member name or string value that is not
    /// well-formed Unicode (contract 1.2). Reading such a value from a parsed
    /// node can throw; that counts as the same finding.
    let surrogateFindings (node: JsonNode) =
        let rec walk (path: string) (current: JsonNode) : string list =
            match current with
            | :? JsonObject as item ->
                item
                |> Seq.toList
                |> List.collect (fun pair ->
                    let child = if path.Length = 0 then pair.Key else $"{path}.{pair.Key}"
                    (if isWellFormed pair.Key then [] else [ child ]) @ walk child pair.Value)
            | :? JsonArray as items -> items |> Seq.toList |> List.mapi (fun i value -> walk $"{path}[{i}]" value) |> List.concat
            | :? JsonValue as value ->
                try
                    match value.TryGetValue<string>() with
                    | true, text when not (isWellFormed text) -> [ path ]
                    | _ -> []
                with :? InvalidOperationException ->
                    [ path ]
            | _ -> []

        walk "" node

    // ----------------------------------------------------------------- keys

    /// "execution", "foreign-execution", "contribution" or "invalid".
    let keyKind (key: string) =
        if executionKey.IsMatch key then "execution"
        elif foreignKey.IsMatch key then "foreign-execution"
        elif contributionKey.IsMatch key then "contribution"
        else "invalid"

    /// `EXT-dokimos.run-7` -> Some "dokimos".
    let foreignSystem (key: string) =
        let m = foreignKey.Match key
        if m.Success then Some m.Groups[1].Value else None

    /// Injective key escaping (contract 1.2): per Unicode code point, ASCII
    /// letters, digits and '-' pass through; everything else, '.' and '_'
    /// included, becomes `_xx` per UTF-8 byte (lower-case hex). So two
    /// different ids never map to the same key, a segment never contains a
    /// '.', and characters outside the BMP are escaped whole: "op 1" ->
    /// "op_201", "vigila.7" -> "vigila_2e7", U+1F600 -> "_f0_9f_98_80".
    /// An empty id, or one that is not well-formed Unicode, cannot form a key.
    let escapeKeySegment (text: string) : Result<string, string> =
        if isNull text || text.Length = 0 then
            Error "a key segment must be a non-empty string"
        elif not (isWellFormed text) then
            Error "a key segment must be well-formed Unicode (unpaired UTF-16 surrogate)"
        else
            let passes (c: int) =
                (c >= int 'A' && c <= int 'Z') || (c >= int 'a' && c <= int 'z') || (c >= int '0' && c <= int '9') || c = int '-'

            text.EnumerateRunes()
            |> Seq.map (fun rune ->
                if passes rune.Value then
                    string (char rune.Value)
                else
                    Encoding.UTF8.GetBytes(rune.ToString()) |> Array.map (fun b -> "_" + b.ToString("x2")) |> String.concat "")
            |> String.concat ""
            |> Ok

    /// Builds an `EXT-<system>.<run-id>` key, escaping the run id with
    /// `escapeKeySegment` and refusing a system or id it cannot carry.
    let foreignExecutionKey (system: string) (runId: string) =
        escapeKeySegment runId
        |> Result.bind (fun segment ->
            let key = $"EXT-{system}.{segment}"

            if foreignKey.IsMatch key && foreignSystem key = Some system then
                Ok key
            else
                Error $"cannot form a foreign execution key from system '{system}' and run '{runId}'")

    /// The key for work known only by an operation id: `EXT-op.<operationId>`,
    /// escaped injectively; Error when the id cannot form a key.
    let operationKey (operationId: string) =
        escapeKeySegment operationId |> Result.map (fun segment -> $"EXT-op.{segment}")

    /// The key Praxis gives a non-agent contributor outside any execution:
    /// `CTB-<UTC day>-<first 8 hex of sha256(kind \0 id)>`, so one actor's
    /// contributions on one day form one entry.
    let outsideExecutionKey (at: DateTimeOffset) (actor: ProvenanceActor) =
        let day = at.ToUniversalTime().ToString("yyyyMMdd", CultureInfo.InvariantCulture)
        use sha = SHA256.Create()

        let digest =
            sha.ComputeHash(Encoding.UTF8.GetBytes($"{actor.Kind}\u0000{actor.Id}"))
            |> Array.map (fun b -> b.ToString "x2")
            |> String.concat ""

        $"CTB-{day}-{digest.Substring(0, 8)}"

    // ------------------------------------------------------------- validation

    let private actorProblems (prefix: string) (node: JsonNode) =
        match node with
        | :? JsonObject as actor ->
            let kind = asString (field actor "kind")

            [ if not (kind |> Option.exists kindPattern.IsMatch) then
                  $"{prefix}.kind is not agent, human, automation, unknown, or x-..."
              if not (isNonEmpty (field actor "id")) then
                  $"{prefix}.id must not be empty; use 'unknown' when it is not known"
              for name in [ "provider"; "model"; "runtime" ] do
                  if present actor name && not (isNonEmpty (field actor name)) then
                      $"{prefix}.{name} must be a non-empty string"

                  if kind = Some "agent" && not (present actor name) then
                      $"{prefix}.{name} is required for an agent ('unknown' when not known)" ]
        | _ -> [ $"{prefix} must be an object" ]

    let private stringListProblems (o: JsonObject) (name: string) (label: string) =
        if not (present o name) then
            []
        else
            match field o name with
            | :? JsonArray as items when items |> Seq.forall isNonEmpty -> []
            | _ -> [ $"{label} must be an array of non-empty strings" ]

    let private operationsOf (entry: JsonObject) =
        match field entry "operations" with
        | :? JsonArray as items -> items |> Seq.choose asString |> Seq.toList
        | _ -> []

    let private contributionProblems (key: string) (node: JsonNode) =
        let prefix = $"contributions.{key}"

        match node with
        | :? JsonObject as entry ->
            let kind = keyKind key

            let operations =
                match field entry "operations" with
                | :? JsonArray as items -> Some(items |> Seq.toList)
                | _ -> None

            let at = asString (field entry "at")

            [ if kind = "invalid" then
                  $"{prefix}: key must be EXE-..., EXT-<system>.<run-id>, or CTB-..."
              match operations with
              | None -> $"{prefix}.operations must be an array"
              | Some [] -> $"{prefix}.operations must record at least one operation"
              | Some items ->
                  for item in items do
                      match asString item with
                      | Some code when operationGrammar.IsMatch code -> ()
                      | _ -> $"{prefix}.operations: an entry is not a valid operation code"

                  let codes = items |> List.map (fun item -> asString item |> Option.defaultValue "\u0000")

                  if (List.distinct codes).Length <> codes.Length then
                      $"{prefix}.operations must not repeat an operation"
              if not (at |> Option.exists (fun value -> (instant value).IsSome)) then
                  $"{prefix}.at must be a calendar-valid ISO-8601 UTC timestamp"
              if present entry "last" then
                  match asString (field entry "last") with
                  | Some last when (instant last).IsSome ->
                      if order last < (at |> Option.map order |> Option.defaultValue Int64.MaxValue) then
                          $"{prefix}.last must not precede at"
                  | _ -> $"{prefix}.last must be a calendar-valid ISO-8601 UTC timestamp"
              if not (present entry "actor") then
                  $"{prefix}.actor is required"
              match field entry "actor" with
              | :? JsonObject as actor when
                  asString (field actor "kind") = Some "agent"
                  && kind <> "execution"
                  && kind <> "foreign-execution"
                  ->
                  $"{prefix}: an agent contribution must be keyed by the execution (EXE-... or EXT-...) that produced it"
              | _ -> ()
              if present entry "reason" && (asString (field entry "reason")).IsNone then
                  $"{prefix}.reason must be a string" ]
            @ (if present entry "actor" then actorProblems $"{prefix}.actor" (field entry "actor") else [])
            @ stringListProblems entry "evidence" $"{prefix}.evidence"
        | _ -> [ $"{prefix} must be an object" ]

    let private creators (contributions: JsonObject) =
        contributions
        |> Seq.toList
        |> List.filter (fun pair ->
            match pair.Value with
            | :? JsonObject as entry -> operationsOf entry |> List.contains "created"
            | _ -> false)

    let private atOf (node: JsonNode) =
        match node with
        | :? JsonObject as entry -> asString (field entry "at") |> Option.defaultValue ""
        | _ -> ""

    let private historyProblems (contributions: JsonObject) =
        match creators contributions with
        | [] -> []
        | [ creation ] ->
            let created = order (atOf creation.Value)

            contributions
            |> Seq.toList
            |> List.filter (fun pair -> pair.Key <> creation.Key && order (atOf pair.Value) < created)
            |> List.map (fun pair -> $"contributions.{pair.Key} precedes the recorded creation ({creation.Key})")
        | many ->
            let keys = many |> List.map (fun pair -> pair.Key) |> String.concat ", "
            [ $"more than one contribution claims 'created': {keys}" ]

    let private classifyObject (node: JsonNode) : ProvenanceVerdict =
        match node with
        | :? JsonObject as block ->
            match credentialFindings block with
            | _ :: _ as secrets ->
                secrets
                |> List.map (fun path -> $"{path}: credential-like value; provenance must never carry authentication material")
                |> ProvenanceVerdict.Malformed
            | [] ->
                let schema =
                    if present block "schema" then
                        match asString (field block "schema") with
                        | Some tag -> Ok(Some tag)
                        | None -> Error "schema must be a string"
                    else
                        Ok None

                match schema with
                | Error problem -> ProvenanceVerdict.Malformed [ problem ]
                | Ok(Some tag) when tag <> SchemaTag ->
                    if schemaPattern.IsMatch tag then
                        ProvenanceVerdict.Unsupported tag
                    else
                        ProvenanceVerdict.Malformed [ $"schema '{tag}' is not a valid praxis.provenance/<major> tag" ]
                | Ok _ ->
                    match field block "contributions" with
                    | :? JsonObject as contributions ->
                        let problems =
                            (contributions |> Seq.toList |> List.collect (fun pair -> contributionProblems pair.Key pair.Value))
                            @ stringListProblems block "derivedFrom" "derivedFrom"

                        if not problems.IsEmpty then
                            ProvenanceVerdict.Malformed problems
                        else
                            match historyProblems contributions with
                            | _ :: _ as invariant -> ProvenanceVerdict.Malformed invariant
                            | [] ->
                                contributions
                                |> Seq.toList
                                |> List.collect (fun pair ->
                                    operationsOf (pair.Value :?> JsonObject)
                                    |> List.filter (fun op -> not (List.contains op knownOperations) && not (extension.IsMatch op))
                                    |> List.map (fun op ->
                                        $"contributions.{pair.Key}.operations: '{op}' is not an operation this version knows; preserved verbatim"))
                                |> ProvenanceVerdict.Supported
                    | null when not (present block "contributions") -> ProvenanceVerdict.Malformed [ "contributions is required" ]
                    | _ -> ProvenanceVerdict.Malformed [ "contributions must be an object keyed by EXE-, EXT-, or CTB- keys" ]
        | _ -> ProvenanceVerdict.Malformed [ "provenance must be a JSON object" ]

    /// Classify a parsed block. Never throws (contract 1.2): a string that is
    /// not well-formed Unicode, or a repeated member name that surfaces only
    /// when the node is enumerated, is malformed. Requirement: AEG-PROV-007.
    let classifyNode (node: JsonNode) : ProvenanceVerdict =
        try
            match surrogateFindings node with
            | [] -> classifyObject node
            | paths ->
                paths
                |> List.map (fun path -> $"{path}: unpaired UTF-16 surrogate; provenance must be well-formed Unicode")
                |> ProvenanceVerdict.Malformed
        with
        | :? ArgumentException as error -> ProvenanceVerdict.Malformed [ $"provenance repeats a member name within one object: {error.Message}" ]
        | :? InvalidOperationException as error -> ProvenanceVerdict.Malformed [ $"provenance is not well-formed: {error.Message}" ]

    /// Member names repeated within any one object, read from the JSON text
    /// itself (contract 1.2): a node-based reader keeps only one of them, so
    /// two readers could disagree about which contribution is real.
    let private duplicateMembers (bytes: byte array) =
        let mutable reader = Utf8JsonReader(ReadOnlySpan<byte>(bytes), JsonReaderOptions(CommentHandling = JsonCommentHandling.Disallow))
        let scopes = Stack<HashSet<string> option>()
        let found = List<string>()

        while reader.Read() do
            match reader.TokenType with
            | JsonTokenType.StartObject -> scopes.Push(Some(HashSet<string>(StringComparer.Ordinal)))
            | JsonTokenType.StartArray -> scopes.Push None
            | JsonTokenType.EndObject
            | JsonTokenType.EndArray -> scopes.Pop() |> ignore
            | JsonTokenType.PropertyName ->
                let name = reader.GetString()

                match scopes.Peek() with
                | Some seen when not (seen.Add name) -> found.Add name
                | _ -> ()
            // Unescaping a string surfaces an unpaired surrogate escape.
            | JsonTokenType.String -> reader.GetString() |> ignore
            | _ -> ()

        found |> Seq.toList

    /// Read provenance JSON text (contract 1.2): text that is not JSON, not
    /// well-formed Unicode, or that repeats a member name within any one
    /// object is malformed, whatever its major version. Never throws.
    let private parse (json: string) : Result<JsonNode, string list> =
        if isNull json then
            Error [ "provenance text is required" ]
        else
            try
                match duplicateMembers (strictUtf8.GetBytes json) with
                | [] ->
                    match JsonNode.Parse json with
                    | null -> Error [ "provenance must be a JSON object" ]
                    | node -> Ok node
                | names -> Error(names |> List.distinct |> List.map (fun name -> $"'{name}': member name repeated within one object"))
            with
            | :? EncoderFallbackException -> Error [ "provenance text is not well-formed Unicode" ]
            | :? JsonException as error -> Error [ $"provenance is not valid JSON: {error.Message}" ]
            | :? InvalidOperationException -> Error [ "provenance holds an unpaired UTF-16 surrogate escape" ]
            | :? ArgumentException as error -> Error [ $"provenance is not valid JSON: {error.Message}" ]

    /// Classify a received block's JSON text. Never throws.
    let classify (json: string) : ProvenanceVerdict =
        match parse json with
        | Ok node -> classifyNode node
        | Error problems -> ProvenanceVerdict.Malformed problems

    let private ofNode (node: JsonNode) =
        match classifyNode node with
        | ProvenanceVerdict.Malformed problems -> Error problems
        | ProvenanceVerdict.Unsupported tag ->
            Ok { text = compact node; schema = tag; supported = false }
        | ProvenanceVerdict.Supported _ ->
            Ok { text = compact node; schema = SchemaTag; supported = true }

    /// Accept a block at the boundary: supported and unsupported blocks are
    /// kept verbatim; malformed ones are rejected with their problems, never
    /// repaired. Requirement: AEG-PROV-007.
    let receive (json: string) : Result<ProvenanceBlock, string list> =
        parse json |> Result.bind ofNode

    /// A new, empty (unattributed) `praxis.provenance/1` block.
    let empty =
        { text = $"{{\"schema\":\"{SchemaTag}\",\"contributions\":{{}}}}"
          schema = SchemaTag
          supported = true }

    // ------------------------------------------------------------- appending

    let private actorNode (actor: ProvenanceActor) =
        let node = JsonObject()
        node["kind"] <- JsonValue.Create actor.Kind
        node["id"] <- JsonValue.Create actor.Id
        actor.Provider |> Option.iter (fun value -> node["provider"] <- JsonValue.Create value)
        actor.Model |> Option.iter (fun value -> node["model"] <- JsonValue.Create value)
        actor.Runtime |> Option.iter (fun value -> node["runtime"] <- JsonValue.Create value)
        node

    let private strings (values: string list) =
        JsonArray(values |> List.map (fun value -> JsonValue.Create value :> JsonNode) |> List.toArray)

    let private contributionNode (c: ProvenanceContribution) =
        let node = JsonObject()
        node["operations"] <- strings c.Operations
        node["at"] <- JsonValue.Create(timestamp c.At)
        node["actor"] <- actorNode c.Actor
        c.Reason |> Option.iter (fun reason -> node["reason"] <- JsonValue.Create reason)

        if not c.Evidence.IsEmpty then
            node["evidence"] <- strings c.Evidence

        node

    let private actorOf (node: JsonNode) =
        match node with
        | :? JsonObject as actor ->
            { Kind = asString (field actor "kind") |> Option.defaultValue Unknown
              Id = asString (field actor "id") |> Option.defaultValue Unknown
              Provider = asString (field actor "provider")
              Model = asString (field actor "model")
              Runtime = asString (field actor "runtime") }
        | _ ->
            { Kind = Unknown
              Id = Unknown
              Provider = None
              Model = None
              Runtime = None }

    /// Same actor: kind, stable id and every known attribute agree; `unknown`
    /// never contradicts.
    let actorsAgree (left: ProvenanceActor) (right: ProvenanceActor) =
        let compatible a b = not (isKnown a && isKnown b) || a = b

        left.Kind = right.Kind
        && (left.Id = right.Id || not (isKnown (Some left.Id)) || not (isKnown (Some right.Id)))
        && compatible left.Provider right.Provider
        && compatible left.Model right.Model
        && compatible left.Runtime right.Runtime

    let private stringsOf (entry: JsonObject) (name: string) =
        match field entry name with
        | :? JsonArray as items -> items |> Seq.choose asString |> Seq.toList
        | _ -> []

    let private merge (key: string) (contribution: JsonObject) (next: JsonObject) =
        let contributions = field next "contributions" :?> JsonObject
        let incomingOps = operationsOf contribution
        let incomingAt = asString (field contribution "at") |> Option.defaultValue ""

        match field contributions key with
        | null ->
            if incomingOps |> List.contains "created" && not (creators contributions).IsEmpty then
                Error "the record already has an originator; record 'modified' instead of 'created'"
            elif
                incomingOps |> List.contains "created"
                && contributions |> Seq.exists (fun pair -> order (atOf pair.Value) < order incomingAt)
            then
                Error "a 'created' contribution cannot follow existing contributions"
            else
                contributions[key] <- contribution.DeepClone()
                Ok true
        | :? JsonObject as existing ->
            let existingActor = actorOf (field existing "actor")
            let incomingActor = actorOf (field contribution "actor")
            let existingOps = operationsOf existing
            let existingAt = atOf existing

            let earlier =
                contributions
                |> Seq.exists (fun pair -> pair.Key <> key && order (atOf pair.Value) < order existingAt)

            if not (actorsAgree existingActor incomingActor) then
                Error $"contribution '{key}' is already attributed to {existingActor.Kind}:{existingActor.Id}; refusing to re-attribute it"
            // Contract 1.1: "unknown" never contradicts, but it never proves
            // the same run either, so it cannot extend a known actor's entry.
            elif
                (isKnown (Some existingActor.Id) && not (isKnown (Some incomingActor.Id)))
                || (existingActor.Kind <> Unknown && incomingActor.Kind = Unknown)
            then
                Error $"contribution '{key}' belongs to {existingActor.Kind}:{existingActor.Id}; an actor with unknown identity cannot extend it"
            elif
                incomingOps |> List.contains "created"
                && not (existingOps |> List.contains "created")
                && (not (creators contributions).IsEmpty || earlier)
            then
                Error "the record's originator is already recorded or precedes this contribution; record 'modified' instead of 'created'"
            else
                let before = compact existing
                let operations = existingOps @ (incomingOps |> List.filter (fun op -> not (List.contains op existingOps)))
                let existingEvidence = stringsOf existing "evidence"
                let evidence = existingEvidence @ (stringsOf contribution "evidence" |> List.filter (fun item -> not (List.contains item existingEvidence)))

                // `last` is the later of the existing (last ?? at) and incoming (last ?? at).
                let existingLatest = asString (field existing "last") |> Option.defaultValue existingAt
                let incomingLatest = asString (field contribution "last") |> Option.defaultValue incomingAt
                let latest = if order incomingLatest > order existingLatest then incomingLatest else existingLatest

                // Unknown (and optional) incoming fields are kept; the existing entry wins on conflict.
                for pair in contribution |> Seq.toList do
                    if pair.Key <> "last" && not (present existing pair.Key) then
                        existing[pair.Key] <- (if isNull pair.Value then null else pair.Value.DeepClone())

                existing["operations"] <- strings operations

                if not evidence.IsEmpty then
                    existing["evidence"] <- strings evidence

                if order latest > order existingAt then
                    existing["last"] <- JsonValue.Create latest

                Ok(compact existing <> before)
        | _ -> Error $"contribution '{key}' is not an object"

    /// Append one contribution given as JSON (so fields Aegis does not model
    /// travel with it), with Praxis's rules: the same key merges operations
    /// and evidence and advances `last` only when the actor agrees; a second
    /// or late `created` is refused; nothing else is touched.
    /// Returns the new block and whether anything changed.
    let private appendNode (key: string) (contribution: JsonObject) (block: ProvenanceBlock) =
        // Contract 1.1: credential-check the incoming contribution (its key
        // included) before anything else.
        let wrapper = JsonObject()
        wrapper[key] <- contribution.DeepClone()

        let problems =
            match surrogateFindings wrapper, credentialFindings wrapper with
            | (_ :: _ as unpaired), _ ->
                unpaired |> List.map (fun path -> $"{path}: unpaired UTF-16 surrogate; provenance must be well-formed Unicode")
            | [], (_ :: _ as secrets) ->
                secrets |> List.map (fun path -> $"{path}: credential-like value; provenance must never carry authentication material")
            | [], [] -> contributionProblems key contribution

        if not block.supported then
            Error $"refusing to append to an unsupported provenance block ({block.schema})"
        elif not problems.IsEmpty then
            Error(String.Join("; ", problems))
        else
            let next = (JsonNode.Parse block.text) :?> JsonObject

            // Contract 1.1: whatever an append returns must itself classify
            // as supported, so the result is re-classified before it is returned.
            merge key contribution next
            |> Result.bind (fun changed ->
                match ofNode next with
                | Ok result when result.supported -> Ok(result, changed)
                | Ok result -> Error $"the resulting history would be unsupported ({result.schema})"
                | Error invalid -> Error("the resulting history would be malformed: " + String.Join("; ", invalid)))

    /// Append one contribution. Requirements: AEG-PROV-003, AEG-PROV-004.
    let append (contribution: ProvenanceContribution) (block: ProvenanceBlock) =
        appendNode contribution.Key (contributionNode contribution) block |> Result.map fst

    /// Append a contribution received as JSON (`{"operations":[...],"at":...,"actor":{...}}`),
    /// preserving every field it carries.
    let appendJson (key: string) (contributionJson: string) (block: ProvenanceBlock) =
        match parse contributionJson with
        | Ok(:? JsonObject as node) -> appendNode key node block
        | Ok _ -> Error $"contributions.{key} must be an object"
        | Error problems -> Error(String.Join("; ", problems))

    /// Add lineage references -- never authorship -- keeping existing order.
    /// Held to the same rules as contributions (contract 1.2): the block must
    /// be supported; every reference must be non-blank (ASCII whitespace),
    /// well-formed Unicode and credential-free; duplicates are dropped
    /// keeping the first occurrence; and the result must classify as
    /// supported. A refusal is an Error -- the lineage is never dropped
    /// silently. Requirement: AEG-PROV-005.
    let addLineage (references: string list) (block: ProvenanceBlock) =
        let indexed = references |> List.mapi (fun i reference -> $"derivedFrom[{i}]", reference)

        if not block.supported then
            Error $"refusing to add lineage to an unsupported provenance block ({block.schema})"
        elif references |> List.exists isBlank then
            Error "lineage references must be non-empty strings"
        else
            match
                indexed |> List.filter (snd >> isWellFormed >> not) |> List.map fst,
                indexed |> List.filter (snd >> isCredentialLike) |> List.map fst
            with
            | (_ :: _ as unpaired), _ -> Error(String.Join(", ", unpaired) + ": unpaired UTF-16 surrogate")
            | [], (_ :: _ as secrets) ->
                Error(String.Join(", ", secrets) + ": credential-like value; provenance must never carry authentication material")
            | [], [] ->
                let next = (JsonNode.Parse block.text) :?> JsonObject
                let current = stringsOf next "derivedFrom"
                let additions = references |> List.distinct |> List.filter (fun reference -> not (List.contains reference current))

                if additions.IsEmpty then
                    Ok block
                else
                    next["derivedFrom"] <- strings (current @ additions)

                    match ofNode next with
                    | Ok result when result.supported -> Ok result
                    | Ok result -> Error $"the resulting lineage would be unsupported ({result.schema})"
                    | Error problems -> Error("the resulting lineage would be malformed: " + String.Join("; ", problems))

    /// Build a block from contributions (in order) and lineage.
    let build (contributions: ProvenanceContribution list) (derivedFrom: string list) =
        contributions
        |> List.fold (fun state contribution -> state |> Result.bind (append contribution)) (Ok empty)
        |> Result.bind (addLineage derivedFrom)

    let private reservedFields = set [ "schema"; "contributions"; "derivedFrom" ]

    /// Carry `source`'s top-level fields that Aegis does not model (anything
    /// but schema, contributions and derivedFrom, e.g. `subject`) into
    /// `block`. A field `block` already holds is kept (the existing value
    /// wins, as in a same-key merge); a different incoming value is returned
    /// as a conflict, never silently dropped. The result must classify as
    /// supported. Requirement: AEG-PROV-004.
    let carryFields (source: ProvenanceBlock) (block: ProvenanceBlock) : Result<ProvenanceBlock * string list, string> =
        if not block.supported || not source.supported then
            Error "refusing to merge fields of an unsupported provenance block"
        else
            let next = (JsonNode.Parse block.text) :?> JsonObject
            let incoming = (JsonNode.Parse source.text) :?> JsonObject

            let additions, conflicts =
                incoming
                |> Seq.toList
                |> List.filter (fun pair -> not (reservedFields.Contains pair.Key))
                |> List.partition (fun pair -> not (present next pair.Key))

            let conflicts =
                conflicts
                |> List.filter (fun pair -> not (JsonNode.DeepEquals(field next pair.Key, pair.Value)))
                |> List.map (fun pair -> $"field {pair.Key} differs from the recorded value; the earlier value is kept")

            if additions.IsEmpty then
                Ok(block, conflicts)
            else
                additions |> List.iter (fun pair -> next[pair.Key] <- (if isNull pair.Value then null else pair.Value.DeepClone()))

                match ofNode next with
                | Ok result when result.supported -> Ok(result, conflicts)
                | Ok result -> Error $"the resulting block would be unsupported ({result.schema})"
                | Error problems -> Error("the resulting block would be malformed: " + String.Join("; ", problems))

    // ------------------------------------------------------------- reading

    let private contributionsNode (block: ProvenanceBlock) =
        if not block.supported then
            None
        else
            match field ((JsonNode.Parse block.text) :?> JsonObject) "contributions" with
            | :? JsonObject as contributions -> Some contributions
            | _ -> None

    /// Every recorded contribution, in the block's order. An unsupported
    /// block is never interpreted, so it yields none.
    let contributions (block: ProvenanceBlock) : RecordedContribution list =
        match contributionsNode block with
        | None -> []
        | Some contributions ->
            contributions
            |> Seq.toList
            |> List.map (fun pair ->
                let entry = pair.Value :?> JsonObject

                { Key = pair.Key
                  Actor = actorOf (field entry "actor")
                  At = atOf entry
                  Last = asString (field entry "last")
                  Operations = operationsOf entry
                  Reason = asString (field entry "reason")
                  Evidence = stringsOf entry "evidence" })

    /// Lineage references (`derivedFrom`).
    let lineage (block: ProvenanceBlock) =
        if block.supported then stringsOf ((JsonNode.Parse block.text) :?> JsonObject) "derivedFrom" else []

    /// The originating (`created`) contribution, or None when origin is not
    /// recorded -- which is never guessed.
    let originator (block: ProvenanceBlock) =
        match contributions block |> List.filter (fun c -> c.Operations |> List.contains "created") with
        | [ creator ] -> Some creator
        | _ -> None

    /// Contributions that played a role (e.g. "validated"), in time order.
    let withRole (operation: string) (block: ProvenanceBlock) =
        contributions block
        |> List.filter (fun c -> c.Operations |> List.contains operation)
        |> List.sortBy (fun c -> order c.At)

    /// True when the block records no contribution (unattributed).
    let isUnattributed (block: ProvenanceBlock) =
        block.supported && (contributions block).IsEmpty

    /// Whether `after` faithfully extends `before`: nothing removed, no actor
    /// or time rewritten, no operation, evidence, field or lineage lost, no
    /// originator replaced; an unsupported block must be unchanged.
    let preservationViolations (before: ProvenanceBlock) (after: ProvenanceBlock) =
        if not before.supported then
            if before.Equals after then [] else [ "unsupported provenance was altered instead of carried verbatim" ]
        elif not after.supported then
            [ "provenance was replaced by an unsupported block" ]
        else
            let b = (JsonNode.Parse before.text) :?> JsonObject
            let a = (JsonNode.Parse after.text) :?> JsonObject
            let bc = field b "contributions" :?> JsonObject
            let ac = field a "contributions" :?> JsonObject

            [ for pair in bc do
                  match field ac pair.Key with
                  | :? JsonObject as later ->
                      let entry = pair.Value :?> JsonObject

                      if not (JsonNode.DeepEquals(field later "actor", field entry "actor")) then
                          $"contribution {pair.Key} actor was overwritten"

                      if atOf later <> atOf entry then
                          $"contribution {pair.Key} time was rewritten"

                      for op in operationsOf entry do
                          if not (operationsOf later |> List.contains op) then
                              $"contribution {pair.Key} lost operation {op}"

                      for item in stringsOf entry "evidence" do
                          if not (stringsOf later "evidence" |> List.contains item) then
                              $"contribution {pair.Key} lost evidence {item}"

                      for name in entry |> Seq.map (fun p -> p.Key) do
                          if not (present later name) then
                              $"contribution {pair.Key} lost field {name}"
                  | _ -> $"contribution {pair.Key} was removed"
              for name in b |> Seq.map (fun p -> p.Key) do
                  if not (present a name) then
                      $"block lost field {name}"
              for reference in stringsOf b "derivedFrom" do
                  if not (stringsOf a "derivedFrom" |> List.contains reference) then
                      $"lineage {reference} was removed"
              let creatorsBefore = creators bc |> List.map (fun p -> p.Key)
              let creatorsAfter = creators ac |> List.map (fun p -> p.Key)

              if creatorsBefore.Length = 1 && creatorsBefore <> creatorsAfter then
                  "the originator was replaced" ]

    // ------------------------------------------------- Aegis-specific roles

    /// A contribution with no reason and no evidence.
    let contribution (key: string) (actor: ProvenanceActor) (at: DateTimeOffset) (operations: string list) : ProvenanceContribution =
        { ProvenanceContribution.Key = key
          Actor = actor
          At = at
          Operations = operations
          Reason = None
          Evidence = [] }

    /// References to the fault's supporting diagnostic material, by
    /// reference only: its environment metadata, snapshot (by digest, never
    /// by location, which may carry access material) and breadcrumb trail.
    /// Requirement: AEG-PROV-006.
    let evidenceOf (fault: Fault) =
        [ match fault.Diagnostics.Environment with
          | Some _ -> $"aegis:fault/{fault.Id.Value}#environment"
          | None -> ()
          match fault.Diagnostics.Snapshot with
          | Some snapshot when not (isBlank snapshot.Digest) -> $"aegis:snapshot/{snapshot.Digest}"
          | _ -> ()
          if not fault.Diagnostics.Breadcrumbs.IsEmpty then
              $"aegis:fault/{fault.Id.Value}#breadcrumbs" ]

    /// The affected artifacts the fault itself names: the commit it was
    /// observed against. Lineage, not authorship. Requirement: AEG-PROV-005.
    let lineageOf (fault: Fault) =
        [ match fault.Diagnostics.Environment |> Option.bind (fun e -> e.CommitSha) with
          | Some sha when not (isBlank sha) -> $"git:commit/{sha}"
          | _ -> () ]

    /// The discovering contribution for a newly recorded fault or finding:
    /// `created` + `discovered`, keyed by the discovering execution, with the
    /// fault's diagnostic material as evidence and the affected artifacts
    /// (the fault's commit plus `affected`) as lineage.
    /// Requirements: AEG-PROV-002, AEG-PROV-005, AEG-PROV-006.
    let discovery (key: string) (actor: ProvenanceActor) (reason: string option) (affected: string list) (fault: Fault) =
        build
            [ { ProvenanceContribution.Key = key
                Actor = actor
                At = fault.Timestamp
                Operations = [ "created"; "discovered" ]
                Reason = reason
                Evidence = evidenceOf fault } ]
            (lineageOf fault @ affected)

    /// The role an Aegis lifecycle event records, by default. Callers may
    /// record other operations explicitly with `build`. Requirement: AEG-PROV-003.
    let operationsFor (ev: AegisEvent) =
        match ev with
        | FaultRecorded _
        | FaultSuppressed _ -> [ "created"; "discovered" ]
        | FaultRepeated _ -> [ "discovered" ]
        | FaultAcknowledged _ -> [ "reviewed" ]
        | RecoveryStarted _ -> [ "remediated" ]
        | RecoveryConcluded _ -> [ "remediated" ]
        | FaultEscalated _ -> [ "modified" ]
        | FaultResolved(_, resolution) when resolution.Verified -> [ "resolved"; "validated" ]
        | FaultResolved _ -> [ "resolved" ]
        | FaultReopened _ -> [ "modified" ]
        | FaultSuperseded _ -> [ "superseded" ]
        | ItemQuarantined _
        | ItemReleased _
        | ItemDeadLettered _
        | SinkFailed _ -> []

    /// When an event's act happened, where the event records it.
    let occurredAt (ev: AegisEvent) =
        match ev with
        | FaultRecorded fault
        | FaultSuppressed(fault, _) -> Some fault.Timestamp
        | FaultRepeated(_, at)
        | FaultAcknowledged(_, _, at)
        | RecoveryConcluded(_, _, _, at)
        | FaultEscalated(_, _, _, at)
        | FaultReopened(_, at, _)
        | FaultSuperseded(_, _, at)
        | ItemReleased(_, at) -> Some at
        | RecoveryStarted(_, attempt) -> Some attempt.Timestamp
        | FaultResolved(_, resolution) -> Some resolution.Timestamp
        | ItemQuarantined item -> Some item.At
        | ItemDeadLettered item -> Some item.At
        | SinkFailed _ -> None

    /// Attribute a lifecycle event to one actor and execution with its
    /// default role (`operationsFor`). For a recorded fault use `discovery`,
    /// which also carries evidence and lineage.
    let attribute (key: string) (actor: ProvenanceActor) (reason: string option) (ev: AegisEvent) =
        match operationsFor ev, occurredAt ev with
        | [], _
        | _, None -> Error $"{ev.GetType().Name} records no contribution role; use Provenance.build"
        | operations, Some at ->
            build
                [ { ProvenanceContribution.Key = key
                    Actor = actor
                    At = at
                    Operations = operations
                    Reason = reason
                    Evidence = [] } ]
                []
            |> Result.map (fun block -> { Event = ev; Provenance = Some block })

    /// Where a block matches a redaction rule. Redaction rules are key-name
    /// rules, so they apply to member NAMES only: every field name other
    /// than a contribution key (which the key grammar already constrains) --
    /// in practice the names of unknown and extension fields. Free-text
    /// VALUES (reason, evidence, lineage, actor fields, unknown fields) get
    /// the contract credential check (`isCredentialLike`) instead, so an
    /// ordinary finding such as "Session cookie lacks the Secure flag" is
    /// accepted while a real token is still refused. Provenance is carried
    /// verbatim, so it is never redacted in place: a block that matches is
    /// rejected instead. Requirement: AEG-PROV-007.
    let redactionFindings (rules: Redaction.Rule list) (block: ProvenanceBlock) =
        let hit (name: string) = rules |> List.tryFind (fun rule -> rule.AppliesTo name)

        let rec walk (path: string) (contributionKeys: bool) (node: JsonNode) : string list =
            match node with
            | :? JsonObject as item ->
                item
                |> Seq.toList
                |> List.collect (fun pair ->
                    let child = if path.Length = 0 then pair.Key else $"{path}.{pair.Key}"

                    let own =
                        match contributionKeys, hit pair.Key with
                        | false, Some rule -> [ $"{child}: field name matches redaction rule '{rule.Name}'" ]
                        | _ -> []

                    own @ walk child (block.supported && path.Length = 0 && pair.Key = "contributions") pair.Value)
            | :? JsonArray as items -> items |> Seq.toList |> List.mapi (fun i value -> walk $"{path}[{i}]" false value) |> List.concat
            | _ ->
                match asString node with
                | Some text when isCredentialLike text -> [ $"{path}: value is credential-like" ]
                | _ -> []

        walk "" false (JsonNode.Parse block.text)

    /// Pair an event with a block that already passed the boundary. Prefer
    /// `attachWith`, which also enforces the configured redaction rules.
    let attach (block: ProvenanceBlock) (ev: AegisEvent) = { Event = ev; Provenance = Some block }

    /// Pair an event with a block, rejecting a block that matches a
    /// redaction rule rather than redacting it in place (provenance is
    /// carried verbatim). Requirement: AEG-PROV-007.
    let attachWith (rules: Redaction.Rule list) (block: ProvenanceBlock) (ev: AegisEvent) =
        match redactionFindings rules block with
        | [] -> Ok(attach block ev)
        | findings -> Error("provenance rejected: " + String.Join("; ", findings))

    /// An event with no provenance: legacy, or genuinely unattributed.
    let unattributed (ev: AegisEvent) = { Event = ev; Provenance = None }


/// The current actor and execution, from explicit declarations only
/// (Praxis RQ-ROS-2026-A016): nothing is guessed from ambient signals, and
/// Praxis need not be installed. Requirement: AEG-PROV-010.
type DeclaredIdentity =
    { Actor: ProvenanceActor
      /// `EXE-...` or `EXT-<system>.<run-id>` when declared.
      Execution: string option }

[<RequireQualifiedAccess>]
module ProvenanceIdentity =

    let private kindPattern =
        Regex("^(agent|human|automation|unknown|x-[a-z0-9][a-z0-9-]*)\\z", RegexOptions.CultureInvariant)

    [<Literal>]
    let private Unknown = "unknown"

    /// The actor nobody declared: every field the literal "unknown".
    let unknownActor =
        { Kind = Unknown
          Id = Unknown
          Provider = Some Unknown
          Model = Some Unknown
          Runtime = Some Unknown }

    /// An agent. Pass "unknown" for anything not known; never invent values.
    let agent id provider model runtime =
        { Kind = "agent"
          Id = id
          Provider = Some provider
          Model = Some model
          Runtime = Some runtime }

    /// A deterministic non-agent process such as CI.
    let automation id provider runtime =
        { Kind = "automation"
          Id = id
          Provider = Some provider
          Model = Some Unknown
          Runtime = Some runtime }

    /// A human. Provider, model and runtime do not apply and are omitted.
    let human id =
        { Kind = "human"
          Id = id
          Provider = None
          Model = None
          Runtime = None }

    /// Resolve the identity from the whitelisted declarations, read through
    /// `lookup` so the function stays pure: ROS_ACTOR_KIND, ROS_ACTOR,
    /// ROS_TELEMETRY_PROVIDER, ROS_TELEMETRY_MODEL, ROS_TELEMETRY_RUNTIME and
    /// ROS_EXECUTION_ID. Undeclared values are "unknown".
    let fromDeclarations (lookup: string -> string option) =
        let read name =
            lookup name |> Option.filter (Provenance.isBlank >> not)

        // Kinds match exactly: "human\n" is not a declaration of "human".
        let declaredKind = read "ROS_ACTOR_KIND" |> Option.filter kindPattern.IsMatch
        let declaredId = read "ROS_ACTOR"
        let kind = declaredKind |> Option.defaultValue Unknown
        let provider = read "ROS_TELEMETRY_PROVIDER"
        let runtime = read "ROS_TELEMETRY_RUNTIME"

        let id =
            match declaredId, provider, runtime with
            | Some declared, _, _ -> declared
            | None, Some p, Some r when kind <> "human" && p <> Unknown && r <> Unknown -> $"{p}/{r}"
            | _ -> Unknown

        let actor =
            if kind = "human" then
                human id
            else
                { Kind = kind
                  Id = id
                  Provider = Some(defaultArg provider Unknown)
                  Model = Some(defaultArg (read "ROS_TELEMETRY_MODEL") Unknown)
                  Runtime = Some(defaultArg runtime Unknown) }

        // Contract 1.1 rule 8: an identity-less process (say, a service
        // started from an agent's shell) must not inherit that agent's run
        // from its environment, or every fault it records would be
        // attributed to the agent. ROS_EXECUTION_ID counts only when the
        // process also declares a kind or an id.
        let execution =
            read "ROS_EXECUTION_ID"
            |> Option.filter (fun _ -> declaredKind.IsSome || declaredId.IsSome)
            |> Option.filter (fun key ->
                match Provenance.keyKind key with
                | "execution"
                | "foreign-execution" -> true
                | _ -> false)

        { Actor = actor; Execution = execution }

    /// The identity this process declared in its environment.
    let current () =
        fromDeclarations (fun name -> Environment.GetEnvironmentVariable name |> Option.ofObj)

    /// The contribution key for an act: the declared execution when there is
    /// one; otherwise `EXT-op.<operationId>` for an agent (which must be keyed
    /// by an execution), or the Praxis `CTB-` key for anyone else. Error when
    /// an agent's operation id cannot form a key (empty, or not well-formed
    /// Unicode); no key is invented.
    let keyFor (operationId: string) (at: DateTimeOffset) (identity: DeclaredIdentity) : Result<string, string> =
        match identity.Execution with
        | Some execution -> Ok execution
        | None when identity.Actor.Kind = "agent" -> Provenance.operationKey operationId
        | None -> Ok(Provenance.outsideExecutionKey at identity.Actor)

/// Accumulates one fault's contribution provenance from its event stream.
/// Pure and append-only: the same events always give the same block.
/// Requirements: AEG-PROV-003, AEG-PROV-004, AEG-PROV-008.
[<RequireQualifiedAccess>]
module ProvenanceHistory =

    let private initial faultId =
        { FaultId = faultId
          Block = Provenance.empty
          Attributed = false
          Carried = []
          Conflicts = []
          Rejected = [] }

    let private foldBlock (label: string) (state: FaultProvenance) (block: ProvenanceBlock) =
        if not block.IsSupported then
            { state with
                Attributed = true
                Carried = state.Carried @ [ block ] }
        else
            let appended, conflicts =
                Provenance.contributions block
                |> List.fold
                    (fun (current, conflicts) recorded ->
                        let entry = System.Text.Json.Nodes.JsonNode.Parse(block.Json).["contributions"].[recorded.Key].ToJsonString()

                        match Provenance.appendJson recorded.Key entry current with
                        | Ok(next, _) -> next, conflicts
                        | Error problem -> current, conflicts @ [ $"{label}: {recorded.Key}: {problem}" ])
                    (state.Block, state.Conflicts)

            let withLineage, conflicts =
                match Provenance.addLineage (Provenance.lineage block) appended with
                | Ok next -> next, conflicts
                | Error problem -> appended, conflicts @ [ $"{label}: {problem}" ]

            // Top-level fields Aegis does not model (e.g. `subject`) survive
            // the fold; the earliest value wins and a differing later one is
            // reported, never silently dropped.
            let withFields, conflicts =
                match Provenance.carryFields block withLineage with
                | Ok(next, differing) -> next, conflicts @ (differing |> List.map (fun problem -> $"{label}: {problem}"))
                | Error problem -> withLineage, conflicts @ [ $"{label}: {problem}" ]

            { state with
                Block = withFields
                Attributed = true
                Conflicts = conflicts }

    /// Fold labelled blocks (in stream order) for one fault. `None` is an
    /// event without provenance: legacy or unattributed, never inferred.
    let ofBlocks (faultId: FaultId) (blocks: (string * ProvenanceBlock option) list) =
        blocks
        |> List.fold
            (fun state (label, block) ->
                match block with
                | Some block -> foldBlock label state block
                | None -> state)
            (initial faultId)

    /// Fold stored provenance (in stream order) for one fault: a rejected
    /// block is recorded under `Rejected`, distinct from an absent one.
    let ofStored (faultId: FaultId) (entries: (string * StoredProvenance) list) =
        entries
        |> List.fold
            (fun state (label, stored) ->
                match stored with
                | StoredProvenance.Carried block -> foldBlock label state block
                | StoredProvenance.Rejected reason -> { state with Rejected = state.Rejected @ [ $"{label}: {reason}" ] }
                | StoredProvenance.Absent -> state)
            (initial faultId)

    /// One fault's accumulated provenance from an attributed event stream.
    let forFault (faultId: FaultId) (events: AttributedEvent list) =
        events
        |> List.filter (fun attributed -> attributed.Event.FaultId = Some faultId)
        |> List.mapi (fun index attributed -> $"event {index} ({attributed.Event.GetType().Name})", attributed.Provenance)
        |> ofBlocks faultId

    /// Every fault's accumulated provenance, keyed by fault id.
    let project (events: AttributedEvent list) =
        events
        |> List.choose (fun attributed -> attributed.Event.FaultId)
        |> List.distinct
        |> List.map (fun faultId -> faultId.Value, forFault faultId events)
        |> Map.ofList
