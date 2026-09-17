# Aegis

A standard mechanism for handling and recovering from unexpected operational
failure in .NET applications — the GitHub call that times out, the stored
file that will not parse, the interop bridge that disappears — without
threading an error type through every method signature, and without
swallowing the failure to make the type signature simpler.

```
dotnet add package EchelonFoundry.Aegis.Core
```

```fsharp
let scope = Aegis.scope config "Chrona.TimeEntry.Load" (Map [ "repository", Public repo ])

match Aegis.capture config scope classifyGitHubFailure (fun () -> repository.load entryId) with
| Ok entries -> render entries
| Result.Error fault -> presentFault (Presentation.present "Unable to load time entries" fault)
```

## Packages

| Package | What it is |
| --- | --- |
| [`EchelonFoundry.Aegis.Core`](https://www.nuget.org/packages/EchelonFoundry.Aegis.Core) | The fault model, capture API, redaction, lifecycle, recovery, escalation, presentation, diagnostics, containment and sink runtime. No third-party dependency at all. |
| [`EchelonFoundry.Aegis.Store.GitHub`](https://www.nuget.org/packages/EchelonFoundry.Aegis.Store.GitHub) | Reference storage adapter: one immutable file per event in a GitHub repository. |
| [`EchelonFoundry.Aegis.Integration.GitHub`](https://www.nuget.org/packages/EchelonFoundry.Aegis.Integration.GitHub) | Typed GitHub failure model and translation into the Aegis fault model. |

## Documentation

- [`docs/aegis/README.md`](docs/aegis/README.md) — the full guide: when to
  use Aegis and when not to, translation, recovery, escalation, testing,
  what Aegis deliberately is not.
- [`docs/aegis/AGENT-INTEGRATION.md`](docs/aegis/AGENT-INTEGRATION.md) — a
  mechanical runbook for an AI coding agent adding Aegis to a codebase.
- [`docs/aegis/REQUIREMENTS-STATUS.md`](docs/aegis/REQUIREMENTS-STATUS.md) —
  every requirement this project was built against, where it is implemented,
  where it is tested, and its current status.
- [`docs/aegis/PUBLISHING.md`](docs/aegis/PUBLISHING.md) — how these
  packages are built and released.
- [`docs/aegis/OPEN-QUESTIONS.md`](docs/aegis/OPEN-QUESTIONS.md) — decisions
  this implementation reached and what remains genuinely open.

## Scope

This repository ships the core, the GitHub storage adapter and the GitHub
integration — nothing else. Database adapters (Postgres, SQL Server,
SQLite) are built elsewhere, against the `Store.T` contract this repository
declares. See
[`DF-AEGIS-2026-DBBD`](research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md)
for why, and what follows from it.

## Repository governance

This repository runs under the Repository Operating System (ROS). Start at
[`AGENTS.md`](AGENTS.md) if you are working on Aegis itself rather than
consuming it as a package.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
