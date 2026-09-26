# Tutela Integration

Aegis observations are security evidence inputs, not security certification.

Requirements:
- Export a provenance-preserving mapping from Aegis observation/fault IDs to Tutela evidence/finding IDs.
- Preserve source, immutable subject ref, observed time, producer/tool version, method and limitations.
- Never map "no Aegis fault" to a Tutela Verified invariant without affirmative evidence.
- Aegis severity MUST NOT independently determine Tutela release posture.
- Redact secrets/sensitive payloads before evidence export.
- Contradictory Aegis observations MUST remain visible.
- Adapter failures MUST create an unknown/indeterminate condition rather than silently dropping evidence.
- Integration schema/version MUST be explicit.
- Contribution provenance (who discovered, remediated, validated) MAY travel as `contributionProvenance`; it MUST NOT be presented as Tutela `provenance` or `producerIdentity` (AEG-PROV-009, requirements/PROVENANCE-INTEGRATION.md).
