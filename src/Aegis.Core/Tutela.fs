namespace Aegis

open System

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
