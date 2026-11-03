# dramatis

The identity tier of the Merely stack. *Dramatis personae*: the persons of
the drama, both you and the other players.

| Crate | Holds |
|---|---|
| [`personae`](crates/personae) | the master keypair, per-protocol derivation, sealed records, the carry model, issuing |
| [`insigne`](crates/insigne) | proofs: typed keys, delegation certificates, revocations and attestations, as plain data; checking behind `verify` |
| [`gaz`](crates/gaz) | stored contacts: anchored records, petnames, per-endpoint trust, kith and kin |
| [`chatelaine`](crates/chatelaine) | the keychain's item taxonomy: every credential kind, described without the secret |
| [`notochord`](crates/notochord) | owner-controlled session admission: delegation chains, owner policy, the revocation ledger |
| [`dramatis`](crates/dramatis) | the facade other repositories pin: the views, intents and receipts hosts render |
| [`castellan-client`](crates/castellan-client) | the application side of castellan's custody route: calls, answers, payloads and, with `client`, the custody and identity clients |

Nothing here holds a secret at rest. Custody (the vault, its storages and
unlock ladder, the SSH agent) is castellan's, in
[mere](https://github.com/merely-made/mere), and only Djinn (mere's resident)
and its independently launched custodian link it. Applications reach identity
by calling Djinn.

This repository depends on no mere crate; `castellan-client` reaches djinn
through Armillary's door contract, `ostiary`, never djinn itself. mere and its siblings pin it by
git revision, and every pin in one build graph must name the same revision,
or personae's types split in two.

Documentation: [`design_docs/DOC_README.md`](design_docs/DOC_README.md).

Licensed under the [Mozilla Public License 2.0](LICENSE).

## Local checks

Enable the commit checks with `prek install --allow-missing-config`; run
`prek run --all-files` alongside the existing local gates. Check definitions
live in `.pre-commit-config.yaml`, with source-size exclusions and exceptions
in `line-ceiling.toml`. Shared house style and rollout: `mere/design_docs/mere_docs/implementation_strategy/2026-10-30_house_style_plan.md`.
