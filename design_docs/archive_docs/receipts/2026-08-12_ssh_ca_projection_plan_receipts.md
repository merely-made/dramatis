# SSH CA projection plan: receipts

Receipts for [the SSH CA projection plan](../../2026-08-12_ssh_ca_projection_plan.md). The plan
cites one hash, in its 2026-10-06 progress line. Its run evidence predates the receipts policy
and is described in the plan's own Findings.

## 2026-11-01, old hashes to main hashes

Mark's ruling (2026-11-01, "Same: live docs only"): live documents cite main hashes; archived documents and receipts keep the hashes they were written with. Each row pairs a hash that is not an ancestor of its repository's main with the commit on main that has the identical subject (`git log main --grep`, exact subject). Hashes that are already ancestors of main are not listed. The repository is the first of dramatis, mere, genet, knot-editor, woodshed, turnstone, cleromancy, murm in which the old hash resolves (murm shares mere's older history). Main hashes are abbreviated to nine characters.

| Old (as written) | Main | Repo | Subject | Cited in (lines at `4c1cd18`) |
| --- | --- | --- | --- | --- |
| `535bca11` | `59118485e` | mere | D2 batch 37 and the S14 pass's phase A done: coverage 337 of 337 | ssh_ca_projection_plan:215 |
