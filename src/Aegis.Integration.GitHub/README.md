# Aegis.Integration.GitHub

A typed GitHub failure model for [Aegis](https://www.nuget.org/packages/EchelonFoundry.Aegis.Core),
and the translation mapping that turns raw GitHub API failures into Aegis
faults at the boundary.

## Install

```
dotnet add package EchelonFoundry.Aegis.Integration.GitHub
```

## What it does

`GitHubFailure.T` is a closed, typed model of what can go wrong calling
GitHub — authentication, rate limiting (with the server's retry-after),
repository-not-found, conflict, timeout, network-unavailable — built with
`ofStatus` and `ofException` from the raw HTTP response or exception. A
`Translation.Mapping<GitHubFailure.T>` declares each case's failure domain,
blast radius, retention and dependencies, so no raw `HttpRequestException`
or `JsonException` ever crosses into your domain code.

```fsharp
match GitHubFailure.ofStatus response with
| Some failure -> Aegis.report config scope (GitHubFailure.mapping) failure
| None -> ()
```

Source: [github.com/kemiller2002/aegis](https://github.com/kemiller2002/aegis) · License: Apache-2.0
