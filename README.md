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
| [`castellan`](crates/castellan) | secret custody: the vault and its unlock ladder, the SSH agent, the wallet's seeds and private epochs, one-time passwords; every release is a gate petition. Linked only by the custodian and the resident, never by an application |
| [`sporran`](crates/sporran) | a persona's wallet on disk: the store adapter for `personae::carry`, with device grants, pairing, revocation, device settings and the wallet-sealed Muniment backend |
| [`djinn-custodian`](crates/djinn-custodian) | the independently launched custody process, installers and native host |
| [`dramatis-surface`](crates/dramatis-surface) | Dramatis as a producer: the roster, quarantine review, vault lock and passphrase change as portable cards plus bounded action forms, over Djinn's custody route. Hosts present it as a pane; there is no Dramatis window |
| [`dramatis-resident`](crates/dramatis-resident) | identity startup, public read models and scoped custody service; host callbacks supply native interaction |
| [`custody-wire`](crates/custody-wire) | the authenticated local custody contract and client, without the vault implementation |
| [`gazette`](crates/gazette) | the directory domain: WebFinger discovery and the intake that hands what it learns to `gaz` |

The independently launched `djinn-custodian` holds Castellan's vault, wallet,
credential catalog and SSH agent. Mere's resident reaches it through
`custody-wire`; applications reach identity through the resident's public door.
The portable identity models and public views remain separate from custody.
The [custody plan](design_docs/2026-10-28_custody_plan.md) keeps the production
deployment gates.

Dramatis has no application of its own. It is a producer: a host (today
Graphshell's viewer, through `graphshell-dramatis-pane`) mounts
`dramatis-surface` and draws its cards, and Djinn still shows the consent and
passphrase prompts. The surface takes Graphshell's projection contract from
crates.io, so this repository names neither Mere nor Graphshell by git.

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
