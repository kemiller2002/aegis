namespace Aegis

open System
open System.Text
open System.Text.Json

/// Minimal, storage-neutral projection of an Aegis fault into Tutela evidence.
/// Aegis reports an observation. Tutela remains responsible for deciding
/// invariant state and release posture.
module Tutela =

    [<Literal>]
    let EvidenceSchema = "tutela/evidence/v1"

    type Evidence =
        { Schema: string
          Id: string
          EvidenceType: string
          Source: string
          SubjectRef: string
          ObservedAt: DateTimeOffset
          Producer: string
          Method: string
          Result: string
          Redacted: bool
          Limitations: string list
          AegisFaultId: string
          AegisCode: string }

    type ProjectionError =
        | MissingImmutableSubjectRef
        | NotSecurityRelevant

    let private resultText (fault: Fault) =
        $"Aegis observed {fault.Code.Value} ({fault.Category}, {fault.Severity}, {fault.Impact}) during {fault.Operation}."

    /// Project a security-classified Aegis fault into evidence.
    /// This function deliberately has no inverse "absence means verified"
    /// operation. Verification requires affirmative Tutela evidence.
    let tryProjectFault (producerVersion: string) (fault: Fault) =
        if fault.Category <> SecurityFailure then
            Error NotSecurityRelevant
        else
            match fault.Diagnostics.Environment |> Option.bind (fun e -> e.CommitSha) with
            | None -> Error MissingImmutableSubjectRef
            | Some subjectRef ->
                Ok
                    { Schema = EvidenceSchema
                      Id = $"AEGIS-{fault.Id.Value}"
                      EvidenceType = "Aegis"
                      Source = "Aegis"
                      SubjectRef = subjectRef
                      ObservedAt = fault.Timestamp
                      Producer = $"EchelonFoundry.Aegis.Core/{producerVersion}"
                      Method = "Security-classified Aegis fault projection"
                      Result = resultText fault
                      Redacted = true
                      Limitations =
                        [ "An Aegis observation is evidence, not a Tutela security conclusion."
                          "Severity does not independently determine Tutela release posture."
                          "The projection intentionally excludes fault context and technical details to avoid propagating sensitive values." ]
                      AegisFaultId = fault.Id.Value
                      AegisCode = fault.Code.Value }

    /// Evidence together with the finding's contribution provenance
    /// (discoverer, remediator, validator, ... and their executions).
    ///
    /// Carried as `contributionProvenance`, never as Tutela's `provenance`
    /// (which means issuer/run attestation) and never as `producerIdentity`:
    /// contribution identity is self-reported and is not authentication,
    /// authorization or evidence weight.
    /// Requirement: AEG-PROV-009.
    type AttributedEvidence =
        { Evidence: Evidence
          ContributionProvenance: ProvenanceBlock option }

    [<Literal>]
    let ContributionProvenanceField = "contributionProvenance"

    /// Project a security finding with its accumulated contribution
    /// provenance (see `ProvenanceHistory`). The projection rules are exactly
    /// those of `tryProjectFault`.
    let tryProjectAttributedFault (producerVersion: string) (provenance: ProvenanceBlock option) (fault: Fault) =
        tryProjectFault producerVersion fault
        |> Result.map (fun evidence ->
            { Evidence = evidence
              ContributionProvenance = provenance })

    /// The projection as `tutela/evidence/v1` JSON. Aegis has no attested
    /// producer identity, artifact digest or issuer attestation, so
    /// `producerIdentity`, `artifactDigest` and `provenance` are absent rather
    /// than invented; a consumer must supply them or treat the record as
    /// incomplete. `contributionProvenance` is the block, verbatim.
    let toJson (attributed: AttributedEvidence) =
        let evidence = attributed.Evidence
        use stream = new IO.MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("schema", evidence.Schema)
        writer.WriteString("id", evidence.Id)
        writer.WriteString("type", evidence.EvidenceType)
        writer.WriteString("source", evidence.Source)
        writer.WriteString("subjectRef", evidence.SubjectRef)
        writer.WriteString("observedAt", evidence.ObservedAt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
        writer.WriteString("producer", evidence.Producer)
        writer.WriteString("method", evidence.Method)
        writer.WriteString("result", evidence.Result)
        writer.WriteBoolean("redacted", evidence.Redacted)
        writer.WritePropertyName "limitations"
        writer.WriteStartArray()

        for limitation in evidence.Limitations do
            writer.WriteStringValue limitation

        writer.WriteEndArray()
        writer.WriteString("aegisFaultId", evidence.AegisFaultId)
        writer.WriteString("aegisCode", evidence.AegisCode)

        match attributed.ContributionProvenance with
        | Some block ->
            writer.WritePropertyName ContributionProvenanceField
            writer.WriteRawValue block.Json
        | None -> ()

        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.ToArray())
