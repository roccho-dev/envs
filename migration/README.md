# Migration lineage

This directory records how the public clean snapshot relates to the former private repository.

## Authority

- Current implementation authority: `roccho-dev/envs@main`
- Canonical migration issue: `roccho-dev/envs#2`
- Historical repository: `roccho-dev/envs-old`
- Historical terminal issue: `roccho-dev/envs-old#137`

The historical repository is evidence only. Current work must be understandable and implementable without private-repository access.

## Records

| File | Meaning |
|---|---|
| `snapshot-source.json` | Exact source commit/tree used for the clean snapshot and the rename-safe repository identity |
| `envs-old-dispositions.jsonl` | One terminal disposition for each issue and pull request that was open in the historical repository at migration review |

The disposition baseline contains exactly:

```text
issues        19
pull requests 16
total         35
duplicate refs 0
unknown items  0
```

## Disposition meanings

| Disposition | Meaning |
|---|---|
| `REAUTHOR_NOW` | A living requirement has a self-contained public issue; implementation starts from current `main` |
| `ABSORB` | The living meaning is already owned by the named current issue |
| `HOLD` | Do not migrate now; the recorded condition must become true before reopening |
| `OWNED_BY_OTHER_REPOSITORY` | The current responsibility belongs to the named repository |
| `RETAIN_PRIVATE_HISTORY` | Keep only as historical evidence |
| `REJECT` | The old candidate was never accepted and is not migrated |
| `SUPERSEDED` | Current architecture or ownership replaces the old path |

No old pull request may be merged or cherry-picked wholesale. A required implementation is rewritten from current public `main`.

## Current public work

- `roccho-dev/envs#2` — clean-snapshot migration and secret/provider boundary
- `roccho-dev/envs#5` — physical g6i3 survey closure
- `roccho-dev/envs#6` — DuckDB binding lifecycle
- `roccho-dev/envs#7` — `chatgpt` read-only SSOT mirror
- `roccho-dev/envs#8` — residual source ownership classification

## Rename-safe references

Before the rename, historical text used `roccho-dev/envs#N`. The old repository now has the name `roccho-dev/envs-old`, while `roccho-dev/envs` names the new public repository.

For migration lineage, the explicit `old_ref` and `current_ref` fields in `envs-old-dispositions.jsonl` are authoritative. An unqualified pre-rename reference is not sufficient to identify current ownership.
