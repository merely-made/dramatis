# Dramatis resident identity service

Identity startup, public read models, scoped custody operations and native
interaction commands over the independently launched custodian. The host
supplies application admission, door wiring, presentation and native dialogs.
The normal dependency graph contains no Mere, Genet, Djinn, dialog backend or
custody implementation. `in-process-custody` adds the explicit test/receipt
host and never supplies a fallback when the custodian refuses.

Mere's graph doors implement their own `DoorIdentity` and `ResidentIdentity`
adapters over this service. Profile environment names, derivation labels,
wire encodings and sealed data formats remain unchanged.

Ownership and qualification: `design_docs/2026-11-01_dramatis_repo_plan.md`, D15.
