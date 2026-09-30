# Dokimos adoption evidence (AEG-DOK-001)

Dokimos 0.1.0 runs as the Aegis quality gate through the pinned reusable
action (`.github/workflows/dokimos.yml`). Evidence lives on branch
`dokimos-evidence`.

| Step | Run | Result |
|---|---|---|
| Pull request gate | PR #5, run 36605479285; re-run on the merged head, run 36611260371 | Installed 0.1.0 with checksum verification; gate `passed`, exit 0 |
| Persistence on `main` | run 36614746656 | Snapshot `kemiller2002/aegis@e1c1380…:8b809bd30e272c84` stored (`dokimos-evidence` `d9f2022`) |
| First baseline | dispatch run 36683592855 (`accept-baseline=true`) | `baselines/default/20260930T072615169Z.json` (`dokimos-evidence` `74e1edf`) |
| History | `dokimos history --store <dokimos-evidence> --repository kemiller2002/aegis` | Returns the snapshot, the baseline and metric series |

To accept a later baseline, run the Dokimos workflow on `main` with
`accept-baseline=true` and a reason.
