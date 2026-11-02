# Dramatis repo plan: receipts

Receipts for the archived [dramatis repo plan](../2026-11-01/2026-10-06_dramatis_repo_plan.md), cut on
2026-11-01 into [the open-work plan](../../2026-11-01_dramatis_repo_plan.md). DOC_POLICY §8 puts run
evidence here and not in the plan. This file indexes it; the evidence itself is not in the repository,
and the archived plan keeps its run narratives as written.

## 2026-11-01, where the evidence lives

These files were tracked in the repository and moved out on 2026-11-01 (Mark: "Move both out"), in commit `6ca6d3a`. Each was written from its committed blob and checked against the blob's SHA-256 before removal; the recorded SHA-256 values inside the plans and manifests are unchanged. `Code/testing` is outside this repository, so these are path cites, not links.

| Path under `Code/testing/dramatis/` | Bytes | SHA-256 |
| --- | --- | --- |
| `testing/receipts/sennet-custody/personae-clippy.log` | 154 | `9b6fa69ba29547e4e004c92c9f9a47b1fc8781a4d224173ea63918a5ff3852b5` |
| `testing/receipts/sennet-custody/personae-tests.log` | 8216 | `8dad0fcb61f29f9f1599fced06d95b179978f2e8b21ce102cd4bebac493b4380` |
| `testing/receipts/sennet-directed/personae-clippy.log` | 1580 | `c8de3efc2e77ac7908046a22833da7ae390b787584094683371b22098fd05233` |
| `testing/receipts/sennet-directed/personae-tests.log` | 6066 | `1a8d3b2099f1bdffea81584563b8d7d6facc1a851925b36507490553622663a1` |
| `testing/receipts/tucket-custody/personae-clippy.log` | 1581 | `b615cca79751c5c2b91bcc90bf7776c674616e4382d94b2d45413d40f58723b5` |
| `testing/receipts/tucket-custody/personae-tests.log` | 7639 | `ab589faa6e0ea84ffff31c3e2890f8fc0bff0a04276283e7c20a3ccce9cfcd8f` |
| `support-receipts/dr_c.json` | 40194 | `22e93a86736d0314a13ab453124dab04a4ca2015c2b9d6be006237d2e74c9f5e` |
| `support-receipts/dr_c_boundary.json` | 954 | `be3d49844c0947b538dd2469597d305faa1b22a8eb04136f04a7511702ba3a6a` |
| `support-receipts/dr_c_logs.zip` | 902446 | `9e25280c32e5d5c98948ba686b7d82393b1091d56c729061ba383f4fd6006762` |
| `support-receipts/chatelaine_cxf_draft.json` | 8236 | `38e9f2125e22864d8b295a18e5c49cb1d9e152b789d2d7249d7b0298ee1ab261` |
| `support-receipts/chatelaine_cxf_draft_logs.zip` | 47290 | `74609af79615acd38b53c4a3e855cc06602a201c3789766114c71bda707c1498` |
| `support-receipts/chatelaine_cxf.json` | 14904 | `e25178f9d820e5dac21f6839b3029a7651c616aad6f68d4032ce8ea69a910a6e` |
| `support-receipts/chatelaine_cxf_logs.zip` | 1257416 | `5257773ab13c7daf1ab5641e8dd22913bb4ab843ee4eba22a0389552dab9a10b` |

The gate runner these receipts came from is mere's `repos/mere/scripts/dr_c_receipts.py`. The DR-C
manifest records 57 commands at their expected exit codes; the bundle `dr_c_logs.zip` holds the 57
command logs and three host logs (bundle SHA-256 as recorded in the plan). The final manifest
`chatelaine_cxf.json` and its bundle are also cited by the chatelaine plan.

## 2026-11-01, inline run evidence in the archived plan

Line numbers are in the archived file, which begins with a two-line archive header (one paragraph and a blank line).

| Evidence | Where |
| --- | --- |
| Tucket custody continuation and the Sennet continuations (71, 73 and 74 Personae tests; Clippy) | lines 5 to 46 |
| DR-A, A0 to A3 (test inventories by name, Windows and Fedora) | from line 712 |
| DR-A done, A4 to A7 (gates on both targets) | from line 750 |
| DR-D built (history carve, pins, measured graphs) | from line 785 |
| DR-B, DR-C and DR-D landed (the combined test run on Windows and Fedora) | from line 819 |
| DR-C closure work (the gate and the control) | from line 856 |
| DR-C closed (57 recorded commands, per-caller table, fallback control) | from line 895 |
| Adoption and publishing preparation (Hocket DPAPI proof, release candidates) | from line 945 |
| Final adoption, CXF import and DR-E publication (318 tests, publish checks) | from line 973 |
| Signalman and documentation follow-up | from line 1020 |
| Notochord secure-channel admission (regression suite description) | from line 1036 |

## 2026-11-01, evidence not retained

- `C:/t/cargo-targets/mere/dr-c-receipts` (the uncompressed DR-C logs): the folder is gone. The same
  logs are in `dr_c_logs.zip`.
- `C:/t/cargo-targets/dramatis` and `C:/t/cargo-targets/retinue` are build caches, not receipts; both
  existed on 2026-11-01.

## 2026-11-01, old hashes to main hashes

Mark's ruling (2026-11-01, "Same: live docs only"): live documents cite main hashes; archived documents and receipts keep the hashes they were written with. Each row pairs a hash that is not an ancestor of its repository's main with the commit on main that has the identical subject (`git log main --grep`, exact subject). Hashes that are already ancestors of main are not listed. The repository is the first of dramatis, mere, genet, knot-editor, woodshed, turnstone, cleromancy, murm in which the old hash resolves (murm shares mere's older history). Main hashes are abbreviated to nine characters.

| Old (as written) | Main | Repo | Subject | Cited in (lines at `4c1cd18`) |
| --- | --- | --- | --- | --- |
| `0234e7e` | `25ead7cfb` | dramatis | Include release licenses and verify refused CXF metadata | dramatis_repo_plan:616, dramatis_repo_plan:953, dramatis_repo_plan:983, dramatis_repo_plan:984 |
| `06d0b59` | `09edaa32a` | woodshed | Pin personae, dramatis and insigne from merely-made/dramatis (dramatis DR-D) | dramatis_repo_plan:815 |
| `13394d83` | `1252b4305` | mere | Close Knot lockstep on the verified Dramatis and CXF graph | dramatis_repo_plan:981 |
| `19be4831` | `440ada716` | dramatis | Derive scoped public Sennet node numbers for Signalman custody | dramatis_repo_plan:20 |
| `39fed3c9` | `ae60ab49a` | mere | kernel: a component copy carries the resource stratum | dramatis_repo_plan:515, dramatis_repo_plan:832 |
| `3aa8828` | `918c7494d` | dramatis | Found the dramatis workspace (DR-D) | dramatis_repo_plan:787 |
| `407bdbe9` | `ebddb6c14` | mere | dramatis repo plan: D18 met (vault lock L2-L4 landed); DR-A reassessed before its... | dramatis_repo_plan:688 |
| `4d8b81c` | `59ec16d9c` | knot-editor | Pin all Mere consumers to the verified CXF and identity graph | dramatis_repo_plan:982 |
| `586167bd` | `cbf09a540` | mere | Route shared content through resource graphs | dramatis_repo_plan:518 |
| `5dca58a9` | `bd0934fdb` | mere | Record viewer validation after the concurrent Dramatis publication | dramatis_repo_plan:842 |
| `6552fa3e` | `7067fd2e8` | mere | dramatis DR-D: the identity tier leaves for merely-made/dramatis | dramatis_repo_plan:814 |
| `65996ea5` | `837ca3f0d` (see note) | mere | Route personae-vault through djinn and add DR-C receipt gates | dramatis_repo_plan:931 |
| `6dfb2fe` | `a5f75fdc1` | woodshed | Require pending refusal for Hocket legacy startup too | dramatis_repo_plan:932 |
| `71a91267` | `6e45e40cf` | mere | Found chatelaine's item taxonomy and move the OTP display enums into it | dramatis_repo_plan:124, dramatis_repo_plan:579, dramatis_repo_plan:706 |
| `762c2fa8` | `0faf125df` | mere | dramatis: the identity surface's views and snapshot move from castellan (DR-A, A4... | dramatis_repo_plan:749 |
| `7af0aec1` | `69075ba39` | mere | dramatis: the identity surface's intent names and payloads move from castellan (D... | dramatis_repo_plan:727 |
| `7cc37a81` | `792ab2590` (see note) | mere | Merge remote-tracking branch 'origin/main' into cxf-import | dramatis_repo_plan:982 |
| `7d333376` | `a59dfc396` | woodshed | Merge main into dr-c and repin Woodshed to mere 5dca58a9 (lockstep with Knot fef1... | dramatis_repo_plan:839 |
| `86f2a3b8` | `65367c7f8` (see note) | mere | Merge remote-tracking branch 'origin/main' into HEAD | dramatis_repo_plan:931 |
| `875060fc` | `a7e2fbb64` | mere | Repin Knot to fef132ef so mere, Knot, woodshed and Turnstone share one mere | dramatis_repo_plan:837 |
| `8b386c9` | `e7aa4f30b` | dramatis | Carry the dramatis tier's history out of mere (DR-D) | dramatis_repo_plan:786 |
| `8d71fa9` | `e5dc7d269` | knot-editor | Add DR-C pending identity receipts for Knot startup | dramatis_repo_plan:932 |
| `8d7880b` | `5152fce6a` | dramatis | Confirm CXF preservation policy and current custody ownership | dramatis_repo_plan:615, dramatis_repo_plan:984 |
| `932d7e05` | `24c0c81e5` (see note) | mere | Complete CLI startup and receipt provenance checks | dramatis_repo_plan:931 |
| `95849ae` | `ed3e0387c` | knot-editor | Integrate shared Tabard appearance authoring into Knot desktop | dramatis_repo_plan:845 |
| `a1a7f1b7` | `15bf800e5` | mere | chatelaine: the Secret Service's metadata moves from castellan (DR-A, A6; ruling ... | dramatis_repo_plan:755 |
| `b31363d2` | `bd1b16a19` | mere | Qualify scoped Sennet release policy and client checks | dramatis_repo_plan:23 |
| `c1d62076` | `22c4bc71d` | dramatis | Found dramatis's design docs: policy, index, links, D2 ledger (DR-D, D19) | dramatis_repo_plan:787, dramatis_repo_plan:803, dramatis_repo_plan:813, dramatis_repo_plan:842 |
| `d54f8aa` | `ade759dcb` | knot-editor | Pin insigne, notochord and personae from merely-made/dramatis (dramatis DR-D) | dramatis_repo_plan:814 |
| `dbad27d5` | `72f1a072c` | mere | dramatis repo plan: rulings D4 (castellan a djinn-only crate, built after vault l... | dramatis_repo_plan:158 |
| `e12788bc` | `570d55dd1` | mere | Merge remote-tracking branch 'origin/main' into codex/sennet-custody | dramatis_repo_plan:22 |
| `e68854f3` | `8fc8f8cf4` | mere | dramatis: the intent receipts move from castellan (DR-A, A5; ruling D31) | dramatis_repo_plan:753 |
| `ea169154` | `e4e2ee8b1` | mere | vault lock plan: rulings 37-39 (cipher zeroize feature on; a resident starting lo... | dramatis_repo_plan:103 |
| `f469b836` | `1da64c6b0` | mere | castellan: the identity snapshot's public JSON pinned byte for byte (dramatis DR-... | dramatis_repo_plan:712 |
| `fef132ef` | `e2ae6f0d6` | knot-editor | Repin Knot to mere 5dca58a9 so Knot, woodshed and Turnstone share one mere | dramatis_repo_plan:838 |



Notes.

- `65996ea5`: two commits on mere main carry its subject (`837ca3f0d`, `a1b9daa07`). `837ca3f0d` has the same patch-id and the same author and committer timestamps (15:13:58 and 15:14:03), so it is the same change re-parented.
- `7cc37a81`: four merge commits on mere main share its subject ("Merge remote-tracking branch 'origin/main' into cxf-import"). `792ab2590` has the same tree (`73cbf4049`) and the same timestamp (2026-10-11 03:59:38). Ambiguous by subject alone; resolved by tree and timestamp.
- `86f2a3b8`: 23 merge commits on mere main share its subject ("Merge remote-tracking branch 'origin/main' into HEAD"). `65367c7f8` has the same tree (`a99c8d59d`), the same timestamps (2026-10-10 15:51:38) and its first parent is `24c0c81e5`, the re-parented `932d7e05`. Ambiguous by subject alone; resolved by tree and timestamp.
- `932d7e05`: two commits on mere main carry its subject (`e5457f80b`, `24c0c81e5`). `24c0c81e5` has the same patch-id and the same author and committer timestamps (15:25:39), so it is the same change re-parented.
