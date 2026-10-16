# dramatis

Secret-free identity contracts for applications using the Djinn resident.
The crate supplies views, intents, operation receipts, and the persona roster.
Apps use these types to request identity operations from Djinn and render the
results. Castellan, composed inside Djinn, owns vault and credential custody.

`subject::SubjectRef` identifies who a saved record concerns independently of
its acting persona: an existing vault profile or a contact's scope and stable
Gaz anchor. It holds no birth facts or disclosure authority. Contact lookup
checks the supplied book's scope and refuses missing records; hosts authorize
access and own any separately held biographical data.

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
