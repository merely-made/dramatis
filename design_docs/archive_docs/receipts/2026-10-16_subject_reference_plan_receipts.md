# Subject references: receipts

Receipts for [the subject reference plan](../../2026-10-16_subject_reference_plan.md).
DOC_POLICY §8 puts run evidence here and not in the plan. This file indexes it; the
evidence itself is not in the repository.

## 2026-11-01, where the evidence lives

The three files below were tracked in `testing/receipts/subject-reference-20261016/`
and moved out on 2026-11-01 (Mark: "Move both out"), in commit `6ca6d3a`. Each was written
from its committed blob and checked against the blob's SHA-256 before removal. They are at
`Code/testing/dramatis/testing/receipts/subject-reference-20261016/` (path cite; `Code/testing`
is outside this repository). The plan cites `publication.json` and `qualification.json`.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `publication.json` | 592 | `f59a39b06f0a7c61c3b54937a2a95640bfaa00e112b717265b263e5e9f65358b` |
| `qualification.json` | 1641 | `92f8e8c6b8f3075425178143c79a059a81a1a54bccbb4eb95b96dbf3591b974b` |
| `tests.log` | 11173 | `55517feb0b3a007d0bd810faa6aa0a20104e01192db19294de1ea39cc7f62220` |

## 2026-11-01, old hashes to main hashes

Mark's ruling (2026-11-01, "Same: live docs only"): live documents cite main hashes; archived documents and receipts keep the hashes they were written with. Each row pairs a hash that is not an ancestor of its repository's main with the commit on main that has the identical subject (`git log main --grep`, exact subject). Hashes that are already ancestors of main are not listed. The repository is the first of dramatis, mere, genet, knot-editor, woodshed, turnstone, cleromancy, murm in which the old hash resolves (murm shares mere's older history). Main hashes are abbreviated to nine characters.

| Old (as written) | Main | Repo | Subject | Cited in (lines at `4c1cd18`) |
| --- | --- | --- | --- | --- |
| `2f27f1a939aa2e046b78f7db18dcd8f81e0d7c59` | `9a147dae6` | dramatis | Release transient Sennet material from the existing scoped child | subject_reference_plan:12 |
| `36ca194` | `ffaad059f` | dramatis | Record verified subject-reference publication | subject_reference_plan:283 |
| `36ca194e5d48c66ae44af9530cc12c9f6a05b0be` | `ffaad059f` | dramatis | Record verified subject-reference publication | subject_reference_plan:16 |
| `cec93f8` | `3162ff7b0` | dramatis | Qualify subject references and document associated-resource boundaries | subject_reference_plan:6 |
