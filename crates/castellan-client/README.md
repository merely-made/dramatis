# castellan-client

The application side of castellan's custody route. An application calls
djinn on its door for identity and secrets; this crate holds those calls,
their answers, sealed payloads and quarantine review, and with `client` the
custody and identity clients that make them. The door's contract is
Armillary's `ostiary`; castellan, which holds the secrets, stays in Mere
beside djinn's resident, and this crate never links either.

| Feature | API | Native | Wasm |
| --- | --- | --- | --- |
| (none) | `custody`, `custody_payload` and `quarantine`: calls, answers, refusals and payload requests | Yes | Gated out |
| `client` | `custody_client` and `custody_identity`, over `ostiary`'s native client | Yes | Gated out |

An application's `AppDeclaration` names the custody it needs; a call is
checked against the owner's grant with `CustodyCall::admitted_by` before the
resident's own floors apply. The wire operations grant nothing by
themselves.
