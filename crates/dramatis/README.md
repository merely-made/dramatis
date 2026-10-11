# dramatis

Secret-free identity contracts for applications using the Djinn resident.
The crate supplies views, intents, operation receipts, and the persona roster.
Apps use these types to request identity operations from Djinn and render the
results. Castellan, composed inside Djinn, owns vault and credential custody.

The identity tier lives in the
[Dramatis repository](https://github.com/merely-made/dramatis): Personae holds
identity and carry primitives, Insigne holds proof grammar, Gaz holds contacts,
Chatelaine holds credential metadata, and Notochord holds admission transcripts.
Those member crates remain separate dependencies; this facade does not
re-export them behind features.

Vault storage, passphrase handling, private SSH slots and credential release
belong to Castellan in [Mere](https://github.com/merely-made/mere). Applications
reach that authority through Djinn's custody route.

## License

MPL-2.0
