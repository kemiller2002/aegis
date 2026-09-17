#!/usr/bin/env bash
# Refuses a NuGet release before it can burn a version.
#
# A NuGet id@version is permanent once pushed: unlisting hides it from search
# but never frees the number for reuse. With three packages, two of which
# depend on the third at an exact version, a mismatch or a version already
# taken is worth catching before any package leaves this machine rather than
# after the first of three pushes succeeds and the rest do not.
#
# Usage: scripts/preflight-nuget-publish.sh VERSION DIST_DIR
set -euo pipefail

version="${1:?usage: preflight-nuget-publish.sh VERSION DIST_DIR}"
dist_dir="${2:?usage: preflight-nuget-publish.sh VERSION DIST_DIR}"

packages=(
  "EchelonFoundry.Aegis.Core"
  "EchelonFoundry.Aegis.Store.GitHub"
  "EchelonFoundry.Aegis.Integration.GitHub"
)

echo "Preflight for ${#packages[@]} packages at ${version}"
echo

problems=0

# Every package this release ships must exist as a .nupkg at this version, so
# a build step that silently skipped one cannot reach the publish step.
for id in "${packages[@]}"; do
  nupkg="${dist_dir}/${id}.${version}.nupkg"
  if [ ! -f "$nupkg" ]; then
    echo "  MISSING: expected ${nupkg}"
    problems=$((problems + 1))
  fi
done

# A dependent package's pin on EchelonFoundry.Aegis.Core must match the
# release version exactly. dotnet pack derives this from the ProjectReference
# automatically, but a stale local build (an old Aegis.Core.dll still sitting
# in bin/) can silently pin an earlier version instead of failing loudly.
for id in "EchelonFoundry.Aegis.Store.GitHub" "EchelonFoundry.Aegis.Integration.GitHub"; do
  nupkg="${dist_dir}/${id}.${version}.nupkg"
  [ -f "$nupkg" ] || continue

  nuspec_entry="$(unzip -Z1 "$nupkg" | grep '\.nuspec$' | head -1)"
  pinned="$(unzip -p "$nupkg" "$nuspec_entry" \
    | grep -o 'id="EchelonFoundry.Aegis.Core" version="[^"]*"' \
    | grep -o '[0-9][^"]*' || true)"

  if [ -z "$pinned" ]; then
    echo "  ${id}: does not declare a dependency on EchelonFoundry.Aegis.Core at all"
    problems=$((problems + 1))
  elif [ "$pinned" != "$version" ]; then
    echo "  ${id}: pins EchelonFoundry.Aegis.Core at ${pinned}, not the release version ${version}"
    problems=$((problems + 1))
  else
    echo "  ${id}: correctly pins EchelonFoundry.Aegis.Core at ${version}"
  fi
done

# A version already on the registry is permanently taken. Check before
# pushing anything, so a re-run after a partial failure stops immediately
# with an explicit remedy instead of failing confusingly mid-loop.
for id in "${packages[@]}"; do
  lower="$(echo "$id" | tr '[:upper:]' '[:lower:]')"
  url="https://api.nuget.org/v3-flatcontainer/${lower}/${version}/${lower}.${version}.nupkg"
  status="$(curl -s -o /dev/null -w '%{http_code}' "$url")"
  if [ "$status" = "200" ]; then
    echo "  ${id}@${version} is ALREADY PUBLISHED"
    problems=$((problems + 1))
  else
    echo "  ${id}@${version} is free"
  fi
done

echo

if [ "$problems" -gt 0 ]; then
  echo "Preflight failed with ${problems} problem(s). Nothing was published."
  exit 1
fi

echo "Preflight passed. Publishing ${#packages[@]} packages at ${version}."
