# Chatelaine and CXF import plan: receipts

Receipts for the archived [chatelaine and CXF import plan](../2026-11-01/2026-10-01_chatelaine_cxf_plan.md),
cut on 2026-11-01 into [the open-work plan](../../2026-11-01_chatelaine_cxf_plan.md). DOC_POLICY §8 puts
run evidence here and not in the plan. This file indexes it; the evidence itself is not in the repository.

## 2026-11-01, where the evidence lives

These files were tracked in the repository and moved out on 2026-11-01 (Mark: "Move both out"), in commit `6ca6d3a`. Each was written from its committed blob and checked against the blob's SHA-256 before removal; the recorded SHA-256 values inside the plans and manifests are unchanged. `Code/testing` is outside this repository, so these are path cites, not links.

| Path under `Code/testing/dramatis/` | Bytes | SHA-256 |
| --- | --- | --- |
| `support-receipts/chatelaine_cxf.json` | 14904 | `e25178f9d820e5dac21f6839b3029a7651c616aad6f68d4032ce8ea69a910a6e` |
| `support-receipts/chatelaine_cxf_logs.zip` | 1257416 | `5257773ab13c7daf1ab5641e8dd22913bb4ab843ee4eba22a0389552dab9a10b` |

The final manifest also records the untouched legacy Signalman desktop failure, the restored original lock,
the existing documentation-audit findings, erasure and per-persona commit limits (as the plan says). The earlier
draft evidence, `chatelaine_cxf_draft.json` and its bundle, is listed in
[the repo plan's receipts](2026-10-06_dramatis_repo_plan_receipts.md). The P5 app slice's evidence is Mere's
`repos/mere/support/receipts/dramatis-app/README.md`, not a file here.

## 2026-11-01, inline run evidence in the archived plan

Line numbers are in the archived file, which begins with a two-line archive header (one paragraph and a blank line).

| Evidence | Where |
| --- | --- |
| Findings: blast radius, SSH algorithms, the P4a real-sshd receipts, the RustSec check | from line 653 |
| Progress, with the per-phase gate records | from line 725 |
| Running it: import landed and the tier published (318 tests, 13 CXF; quarantine tripwire) | from line 988 |
| Desktop and documentation follow-up (Signalman refresh) | from line 1035 |
| P5 first app slice receipt (16 custody tests, 303 Castellan tests, consent No/Yes, five captures) | from line 1126 |

## 2026-11-01, evidence not retained

The per-lane `CARGO_TARGET_DIR`s under `C:\t\cargo-targets\mere\` named in section 6 are build output, not
receipts, and are not kept. `C:/t/cargo-targets/retinue` existed on 2026-11-01.

## 2026-11-01, old hashes to main hashes

Mark's ruling (2026-11-01, "Same: live docs only"): live documents cite main hashes; archived documents and receipts keep the hashes they were written with. Each row pairs a hash that is not an ancestor of its repository's main with the commit on main that has the identical subject (`git log main --grep`, exact subject). Hashes that are already ancestors of main are not listed. The repository is the first of dramatis, mere, genet, knot-editor, woodshed, turnstone, cleromancy, murm in which the old hash resolves (murm shares mere's older history). Main hashes are abbreviated to nine characters.

| Old (as written) | Main | Repo | Subject | Cited in (lines at `4c1cd18`) |
| --- | --- | --- | --- | --- |
| `007fbe7c` | `6f4b88b73` | mere | Merge chatelaine P4a: the agent signs RSA through ring and ECDSA; held keys untou... | chatelaine_cxf_plan:9, chatelaine_cxf_plan:924 |
| `0234e7e` | `25ead7cfb` | dramatis | Include release licenses and verify refused CXF metadata | chatelaine_cxf_plan:992, chatelaine_cxf_plan:1026 |
| `0891771f` | `ffdf7cf93` | mere | castellan: the Secret Service on chatelaine items (P3) | chatelaine_cxf_plan:827 |
| `13394d83` | `1252b4305` | mere | Close Knot lockstep on the verified Dramatis and CXF graph | chatelaine_cxf_plan:989 |
| `23e2b43b` | `de5800fcd` | mere | Keep castellan's items on chatelaine, one sealed payload per credential, and move... | chatelaine_cxf_plan:766 |
| `2d2a36c6` | `5712fec10` | mere | personae agent signs RSA through ring and ECDSA beside Ed25519 (chatelaine P4a) | chatelaine_cxf_plan:885, chatelaine_cxf_plan:924 |
| `3e4992ec` | `b9d4cebbf` | mere | Merge chatelaine P2: castellan's items on chatelaine, OTP on the item store | chatelaine_cxf_plan:6, chatelaine_cxf_plan:767 |
| `4c4ce3bc` | `7288e7ef9` | mere | personae-vault add-ssh joins the other two SSH import doors (chatelaine ruling 60) | chatelaine_cxf_plan:925 |
| `4d8b81c` | `59ec16d9c` | knot-editor | Pin all Mere consumers to the verified CXF and identity graph | chatelaine_cxf_plan:990 |
| `62e69f13` | `a5af71884` | mere | P4a: rsa builds RSA keys and ring signs; held keys untouched; unsignable keys ref... | chatelaine_cxf_plan:925 |
| `71a91267` | `6e45e40cf` | mere | Found chatelaine's item taxonomy and move the OTP display enums into it | chatelaine_cxf_plan:698 |
| `7cc37a81` | `792ab2590` (see note) | mere | Merge remote-tracking branch 'origin/main' into cxf-import | chatelaine_cxf_plan:993 |
| `8d7880b` | `5152fce6a` | dramatis | Confirm CXF preservation policy and current custody ownership | chatelaine_cxf_plan:1025 |
| `d0d8372b` | `e329b2699` | mere | Chatelaine resumes at P4a (rulings 51-53); pairing pauses before D2 (73-74) | chatelaine_cxf_plan:885 |
| `d5f60e5c` | `8f7733dfc` (see note) | mere | Merge remote-tracking branch 'origin/main' into cxf-import | chatelaine_cxf_plan:1001 |
| `da3c50bc` | `59475aefd` | mere | Say what the chatelaine crate holds: identifying metadata, with persona scope on ... | chatelaine_cxf_plan:6, chatelaine_cxf_plan:746 |
| `dfee134a` | `7cb05cad4` | mere | ssh_sign: the rsa crate builds an RSA key once per signature, not per load (rulin... | chatelaine_cxf_plan:925, chatelaine_cxf_plan:934 |
| `e7c8acbd` | `6b15a209c` | mere | castellan: a refusal test per Secret Service limit, on the pre-P3 store | chatelaine_cxf_plan:813, chatelaine_cxf_plan:826 |
| `eb79b36e` | unmatched (see note) | mere | Merge chatelaine P4a: the agent signs RSA through ring and ECDSA; held keys untou... | chatelaine_cxf_plan:926 |
| `f0141e3a` | `b2be78731` | mere | Keep CXF source ids on chatelaine items, and rename Totp to Otp | chatelaine_cxf_plan:739 |
| `f7b31b9a` | `6a4f4f5e5` | mere | Record rulings 43 to 45: the ThinkPad found, the Linux target, P2's readings | chatelaine_cxf_plan:802 |
| `f8734195` | unmatched (see note) | mere | Merge chatelaine P1: the item taxonomy and the OTP display enums | chatelaine_cxf_plan:700 |
| `ff68e86c` | `becbff0a2` | mere | Merge chatelaine P3: the Secret Service on chatelaine items | chatelaine_cxf_plan:7, chatelaine_cxf_plan:827 |
| `ff78acca` | `8d626fcec` | mere | graph semantics plan: rulings 5-8 and final phases P1-P5 with checkpoints C1-C6 | chatelaine_cxf_plan:926 |

Notes.

- `7cc37a81`: four merge commits on mere main share its subject ("Merge remote-tracking branch 'origin/main' into cxf-import"). `792ab2590` has the same tree (`73cbf4049`) and the same timestamp (2026-10-11 03:59:38). Ambiguous by subject alone; resolved by tree and timestamp.
- `d5f60e5c`: the same four merges. `8f7733dfc` has the same tree (`c4e21119a`) and the same timestamp (2026-10-11 04:04:04). Ambiguous by subject alone; resolved by tree and timestamp.
- `eb79b36e` ("Merge chatelaine P4a ... (rulings 25, 51-60)"): no commit on mere main has this exact subject. The merge on main is `6f4b88b73` (rulings 25, 51-63), which is also where `007fbe7c` maps; the two were different merges of the same line. Not mapped.
- `f8734195` ("Merge chatelaine P1: the item taxonomy and the OTP display enums"): no commit on mere main has this exact subject. The nearest is `7ca545acb` ("Merge chatelaine P1: the item taxonomy, CXF source ids, and the OTP display enums"), a differently worded merge; its second parent is the content commit `71a91267`, which maps to `6e45e40cf`. Not mapped.

Hashes that are not commits:

- `bc629d2e` (plan line 909) is the leading hex of a `sha256` of an `authorized_keys` file, and `ef6173cb` (line 911) is a commit of the RustSec advisory database. Neither is a commit of any family repository, so neither is mapped.
- `ed25519` (line 661) matched the hash pattern and is a key algorithm.
