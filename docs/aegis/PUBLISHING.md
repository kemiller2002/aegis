---
id: GV-AEGIS-005
title: Publishing Aegis to NuGet
status: draft
version: 1.0.0
owners:
  - repository-governance
created: 2026-09-17
related_documents:
  - docs/aegis/README.md
  - docs/aegis/AGENT-INTEGRATION.md
  - .github/workflows/publish-nuget.yml
  - scripts/preflight-nuget-publish.sh
tags: [aegis, documentation, publishing, nuget]
---

# Publishing Aegis to NuGet

Three packages, one version number, one release: `EchelonFoundry.Aegis.Core`,
`EchelonFoundry.Aegis.Store.GitHub` and `EchelonFoundry.Aegis.Integration.GitHub`.
The latter two depend on an exact version of the first, so a partial release
would leave a dependent package pointing at a Core version that was never
published — [`.github/workflows/publish-nuget.yml`](../../.github/workflows/publish-nuget.yml)
builds, tests, packs and pushes all three in one run for exactly that reason.

## How a release happens

Push a tag `aegis-vX.Y.Z`, or run the workflow manually
(Actions → Publish Aegis to NuGet → Run workflow → version `X.Y.Z`). Either
way the pipeline is: restore, build, run the full test suite, pack all three
projects at that version, then preflight and push.

`dotnet pack` derives each dependent package's pin on `EchelonFoundry.Aegis.Core`
from the `ProjectReference` automatically — nothing hand-maintains that
version number, which is what keeps it from drifting.

## The preflight

[`scripts/preflight-nuget-publish.sh`](../../scripts/preflight-nuget-publish.sh)
runs before anything is pushed, and refuses the release when:

- a package this release should ship did not get packed (a build step that
  silently skipped one would otherwise reach the publish step);
- a dependent package's pin on `EchelonFoundry.Aegis.Core` does not match
  the release version (a stale local build could otherwise ship a mismatch);
- any of the three versions already exists on the registry.

A NuGet `id@version` is permanent once pushed — unlisting hides it from
search but never frees the number for reuse — so the third check is what
protects a re-run: if a release ever publishes partway and then fails, the
next attempt at the same version stops immediately rather than failing
confusingly mid-loop.

## Trusted Publishing (OIDC), and the one-time setup it needs

The workflow authenticates to nuget.org via
[Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing):
it requests a GitHub OIDC token (`permissions: id-token: write`) and
exchanges it through `NuGet/login@v1` for a short-lived nuget.org API key,
so no `NUGET_API_KEY` secret is stored in this repository at all.

That exchange only succeeds once a **Trusted Publishing policy** on
nuget.org names this exact repository and workflow file. One-time setup,
on nuget.org, by whoever owns the `EchelonFoundry` packages there:

1. Sign in to nuget.org, click your username → **Trusted Publishing**.
2. **Add a policy** with:
   - **Repository Owner:** `kemiller2002`
   - **Repository:** `aegis`
   - **Workflow File:** `publish-nuget.yml`
   - **Package glob:** `EchelonFoundry.Aegis*`
3. Save it.

**If nuget.org refuses a policy scoped to packages that do not exist yet**
(unconfirmed at the time this was written — Trusted Publishing policies are
account-scoped with a glob, which suggests they can precede the package,
but this repository has not verified it against a brand-new package
prefix): fall back to a one-time manual publish, the same shape as this
repository's earlier npm bootstrap under
[`DF-AEGIS-2026-DBBD`](../../research/decisions/DF-AEGIS-2026-DBBD--aegis-repository-scope.md)'s
sibling project —

1. Generate a classic nuget.org API key (Account Settings → API Keys →
   Create, scoped to "Push new packages and package versions", pattern
   `EchelonFoundry.Aegis*`).
2. Run `scripts/preflight-nuget-publish.sh` and `dotnet nuget push` once,
   locally or via a temporary `NUGET_API_KEY` repository secret, to create
   the three packages.
3. Return to step 1 above — the policy can now be attached to packages that
   exist, and the temporary secret can be deleted.

## Package identity

`EchelonFoundry.Aegis.Core` was chosen over the shorter `Aegis.Core` because
`Aegis.Core` is already taken on nuget.org by an unrelated package (checked
against the live registry before this convention was adopted). The
`EchelonFoundry.` prefix is free across the whole namespace and matches the
`@echelon-foundry` npm scope this organization already publishes under.

## Versioning

All three packages move together at one semantic version. There is no
independent versioning of `Aegis.Store.GitHub` or `Aegis.Integration.GitHub`
from `Aegis.Core` — they are thin, and a version skew between them and the
core they depend on is a bug class this repository does not want to carry.
