# Subject references for saved natal readings

**Date:** 2026-10-16

**Status:** bounded reference implemented locally for review; birth-fact storage
ownership proposed, unresolved. No consumer integration or publication.

**Source base:** Dramatis `2f27f1a939aa2e046b78f7db18dcd8f81e0d7c59`, fetched
`origin/main`. Deciders: maintainer and receiving Cleromancy/resident owners.

## Context and source findings (2026-10-16)

The subject of a reading may be someone other than its author or acting persona.
Requiring a credential profile for that person would confuse a biographical
subject with an actor. The [tier architecture](2026-09-30_dramatis_tier_architecture.md)
separates identity vocabulary from resident authority and the data plane.

- `personae::ProfileId` is a string wrapper identifying a profile **within a
  vault** (`crates/personae/src/vault.rs`). `ProfileSummary` and `PublicProfile`
  describe identity/key posture, including what stays visible while locked.
  `PersonaId` is a separate UUID type (`crates/personae/src/lib.rs`); neither
  implies a conversion to Gaz's scope labels.
- `dramatis::view::ProfileView` and `roster::{RosterEntry, Roster}` are public
  identity/picker views. They have no birth-fact contract. Their fields and
  serialized forms remain unchanged.
- Gaz's `Contact` has a stable `Anchor`, and `ContactBook` provides `scope()`,
  `verify_scope()` and `get(&Anchor)` (`crates/gaz/src/{contact,book,anchor}.rs`).
  A key rotation changes the root line, not the anchor. `Contact::new_local`
  takes a caller-supplied `LocalId` and requires no key, profile or login.
- Anchors already serialize to identifier text in JSON and tagged variants in
  binary. Gaz validates anchors and contact relationships on deserialize;
  retained proof data is not a successful authenticity or admission check.
- Gaz's optional `muniment` persistence uses host-selected storage, codec and
  sealing, and rejects mis-filed scopes (`crates/gaz/src/persistence.rs`).
  `jscontact::PublicCard` selects publication fields explicitly, with no
  conversion from a private `Contact`. `publish`, `export_contact`,
  `restore_contact` and unverified `import` are separate paths
  (`crates/gaz/src/jscontact/{mod,exchange}.rs`). A raw Card can retain opaque
  fields; that does not make those fields an admitted biographical record.
- Chatelaine's identity-document taxonomy recognizes sealed `birth_date` and
  `birth_place` payload fields (`crates/chatelaine/src/kind_tests.rs`). That
  describes credential content, not a reusable birth-facts service or consent
  to disclose one. Castellan custody stays in Mere; Notochord's session
  admission is not a natal-data grant.

## Bounded decision and public API

Dramatis supplies **only a reusable subject reference** in this slice:
`dramatis::subject::{SubjectRef, SubjectLookupError}`. The compile-ready type is
in `crates/dramatis/src/subject.rs`:

```rust
// Illustrative usage; ProfileId, PersonaScope and Anchor remain owned types.
SubjectRef::Profile { id: profile_id }
SubjectRef::Contact { scope: book_scope, anchor: original_anchor }
```

The facade directly depends on the existing workspace Gaz crate, with neither
`muniment` nor `jscontact` enabled by this dependency. It does not move Gaz's
types or introduce a reverse dependency. No dependency revisions or versions
change; Cargo's lock change adds only the facade's Gaz and test-codec edges.

JSON uses `{"Profile":{"id":"work"}}` or
`{"Contact":{"scope":"work","anchor":"urn:uuid:…"}}`. The namespaces are
explicit; unknown variants/fields and malformed anchors refuse. Binary keeps
the declared variant order (Profile 0, Contact 1) and existing nested formats.
Future variants must preserve order. The receiving saved-record envelope owns
schema versioning and resident/vault context: these references alone are not
globally unique or portable between unrelated residents.

`resolve_contact(&ContactBook)` is a structural lookup against a book the host
has **already authorized**. It refuses a profile, a different scope (using
Gaz's existing `ScopeMismatch`), or a missing contact. It never creates a
contact, searches a petname/current key, changes trust, or falls back to the
acting persona. Profile existence/access stays with the resident. A typed
reference is forgeable input, not authority; successful lookup grants no
access to birth facts. Scope labels and opaque profile ids retain existing
validation semantics, including acceptance of arbitrary strings.

## Birth-fact ownership alternatives

| Alternative | Assessment |
|---|---|
| Put facts in public profiles/rosters | Reject: expands a public identity surface and couples private biography to login/key posture. |
| Treat credential payloads as the birth database | Reject for C8: document fields exist, but custody/release does not establish a canonical person biography or authorize automatic disclosure. |
| Extend Gaz Contact / JSContact publication | Defer: Gaz owns local relationships and exchange; natal uncertainty, historical civil time and a general biography domain have no current contract. This would change stored contact ownership and wire policy. |
| Resident-held personal-data domain, referenced by identity | Recommend: identity stays here; admitted biographical facts, revisions, access and lifecycle live with a named resident data owner. Its exact module/schema is a maintainer decision. |

The recommendation is an architectural boundary, **not an assertion that this
repository already supplies that service**. No birth storage, persistence
owner, permissions model or credential-release route is implemented here.
If no authorized contact exists, the consumer must explicitly admit a local
contact through the existing host path, or defer linking and retain a
consumer-owned reading snapshot; deserializing `SubjectRef` cannot do that.

## Receiving-consumer requirements

1. Save subject separately from actor/author. Keep the resident/vault context,
   and use the book's actual opaque scope rather than guessing it from a
   `ProfileId` or `PersonaId`. Do not silently link by display name. Missing,
   deleted or inaccessible subjects remain unresolved; never retarget a saved
   reading. Keep an authorized immutable input snapshot or admitted fact
   revision reference so edits to a contact do not rewrite a historical chart.
2. The future data owner must preserve original civil date, calendar and
   supplied local time independently of any conversion. Time has explicit
   **known**, **unknown** and **approximate** cases. Unknown has no invented
   noon/midnight. Approximate records the supplied estimate, uncertainty
   interval or stated precision, and its source; it is not an exact instant.
3. Preserve place as entered, selected place identity/coordinates when known,
   coordinate/place precision and provenance separately. An inferred city
   centre is not a precise birthplace. Record whether information was entered,
   reported, document-derived or resolved, with source/revision evidence.
4. Historical timezone resolution is a separate result: zone identifier,
   resolver/dataset version, relevant date, candidate offsets/instants,
   ambiguity or gap/refusal, and any explicit disambiguation. Calculated UTC
   and calculation provenance derive from these inputs; never overwrite the
   original civil facts or claim a unique UTC instant from uncertain input.
   Numerical/time integration and interpretation eligibility belong to the
   parent lane, including which claims unknown/approximate times permit.
5. The resident data owner controls admission, retention and explicit release
   of biographical facts under existing host authority. Contact-book access,
   a public card, a credential view or a saved subject reference is not that
   release. This slice creates no new permission system.
6. Keep existing saved readings, digests and receipts frozen. In particular,
   Cleromancy's edition-1 rationale explicitly excludes birth charts, houses
   and a rising sign (`repos/cleromancy/src/content/astrology-prompts-v1.json`).
   C8 needs its own versioned natal inputs/claims; do not reinterpret edition 1.
   The consumer source was read only as a boundary locator, not qualified here.

## Phases and validation

- Reference slice: done when existing types remain unchanged, the additive
  contract round-trips JSON/Postcard and refuses malformed references, wrong
  scopes and missing records. Locally implemented; test evidence below.
- Resident biography ownership: open. Done only after the maintainer names
  an owner and approves its versioned facts, admission and disclosure contract.
- Consumer adoption: parent-owned and open. Requires explicit natal versioning,
  real saved input/replay evidence, and separate native/fresh-process receipts.

## Progress (2026-10-16)

- Added the plain reference and structural lookup, without modifying existing
  views, receipts, Gaz records, Personae or Chatelaine types.
- Seven supplier tests pass: exact JSON and binary fixtures; every existing
  anchor family; malformed/augmented input refusal; a keyless other person
  after book serialization/reload; cross-scope/missing/profile refusal; and
  rename/rotation stability with deletion refusing to retarget by name.
- Validation on Rust/Cargo 1.97.1: `cargo test -p dramatis --offline` passes
  seven tests; `cargo test -p dramatis -p gaz --all-features --locked` passes
  seven Dramatis tests, 92 existing Gaz tests and four Gaz doctests. The latter
  downloaded the already locked Muniment 0.1.2 after an offline attempt found
  it absent. `git diff --check` and focused Rustfmt checks pass. Normal-edge
  `cargo tree -p dramatis -e normal --locked --offline` confirms Gaz adds no
  Muniment persistence or JSContact exchange dependency to the facade.
- No consumer, native, durable resident storage, credential disclosure,
  historical-time or numerical qualification is claimed.
