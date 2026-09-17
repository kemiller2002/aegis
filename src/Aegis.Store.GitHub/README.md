# Aegis.Store.GitHub

The GitHub storage adapter for [Aegis](https://www.nuget.org/packages/EchelonFoundry.Aegis.Core):
one immutable file per event, at `<root>/YYYY/MM/DD/<eventId>.json`, with
zero-padded identifiers so lexical order matches chronological order.

## Install

```
dotnet add package EchelonFoundry.Aegis.Store.GitHub
```

## What it does

- **Append-only.** A write refuses to overwrite an existing event file; a
  batch checks every path before committing any of them.
- **No GitHub API client.** Repository operations are injected as an
  `Operations` record, so this package carries no HTTP or auth dependency of
  its own — you supply whatever client you already use to talk to GitHub.
- **An async sink.** It advertises batch support and integrates directly
  with `Aegis.Core`'s sink runtime.

```fsharp
let operations : Aegis.Store.GitHub.Operations = {
    Read = readFile
    Write = writeFile
    // ...
}
let store = Aegis.Store.GitHub.create config operations
```

## Scope

Database adapters (Postgres, SQL Server, SQLite) are deliberately **not**
part of this repository — they belong outside it, built against the same
`Store.T` contract this adapter exercises, with the code that owns each
engine's driver. See
[`DF-AEGIS-2026-DBBD`](https://github.com/kemiller2002/aegis/blob/main/research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md).

Source: [github.com/kemiller2002/aegis](https://github.com/kemiller2002/aegis) · License: Apache-2.0
