# Gaz founding plan: receipts

Receipts for the archived [gaz founding plan](../2026-11-01/2026-08-08_gaz_founding_plan.md), cut on 2026-11-01
into [the open-work plan](../../2026-11-01_gaz_plan.md). DOC_POLICY §8 puts run evidence here and not in the
plan. This file indexes it; the plan keeps its run narratives as written.

## 2026-11-01, where the evidence lives

No receipt file of this plan was tracked in the repository, so none moved. The raw logs it names were kept in
folders under `C:\t\cargo-targets\mere\`, and none exists any more:

| Folder | Cited at (archived plan) | State on 2026-11-01 |
| --- | --- | --- |
| `gaz-jscontact-receipts` | line 334 | not retained |
| `gaz-m1-receipts` | line 626 | not retained |
| `gaz-sealing-receipts` | line 682 | not retained |
| `gaz-m2-receipts` (and its `gates-integrated.json` index) | lines 770 and 797 | not retained |

What survives is each slice's narrative record in the plan and the tests in the repositories that hold them
(`repos/mere/ports/mere-resident/castellan/tests/sealed_contacts.rs` and `sealed_webfinger_intake.rs`; gaz's own
tests under `crates/gaz/`).

## 2026-11-01, inline run evidence in the archived plan

| Evidence | Where |
| --- | --- |
| M1 JSContact receipt (82 unit tests, mutation control, Wasm check) | line 328 |
| M1 storage gates (66 tests, scope-check mutation) | line 624 |
| M1 host sealing gate (castellan sealed-contact receipts) | line 681 |
| M2 final gates (92 unit tests and four doctests; Gazette 20; Castellan 76; Clippy; Wasm; mutation) | line 768 |
| Progress headings: M2 unverified address intake and supplied WebFinger adapter; S14 pass | from lines 718 and 800 |

## 2026-11-01, old hashes to main hashes

Mark's ruling (2026-11-01, "Same: live docs only"): live documents cite main hashes; archived documents and receipts keep the hashes they were written with. Each row pairs a hash that is not an ancestor of its repository's main with the commit on main that has the identical subject (`git log main --grep`, exact subject). Hashes that are already ancestors of main are not listed. The repository is the first of dramatis, mere, genet, knot-editor, woodshed, turnstone, cleromancy, murm in which the old hash resolves (murm shares mere's older history). Main hashes are abbreviated to nine characters.

| Old (as written) | Main | Repo | Subject | Cited in (lines at `4c1cd18`) |
| --- | --- | --- | --- | --- |
| `535bca11` | `59118485e` | mere | D2 batch 37 and the S14 pass's phase A done: coverage 337 of 337 | gaz_founding_plan:800 |
| `5364dfa0` | `4349d7320` | mere | Move delegation and attestation proofs into insigne (proofs plan phase A) | gaz_founding_plan:357 |
| `8425cd73` | `500b6a9fa` | mere | Merge remote-tracking branch 'origin/main' into codex/reference-data | gaz_founding_plan:766 |
| `b1eb3af1` | `f499efe46` | genet | Place host text paint inside Livery field contexts | gaz_founding_plan:767 |
| `c5470fcb` | `fcfe8087c` | genet | Share retained generated names and resolve decimal counters | gaz_founding_plan:639 |
| `ca2351b3` | `c55a420dc` | mere | Add bounded Apparatus observations and optional Mesquite receipts | gaz_founding_plan:640 |
| `cf901f3d` | `959e53b5e` | mere | Add Gaz JSContact exchange with unverified peer intake | gaz_founding_plan:712 |
| `d82afa17` | `d7dbf6b6e` | mere | Generate the Circuit workspace graph instead of committing it | gaz_founding_plan:201 |
