# Subject references for saved natal readings

**Date:** 2026-10-16

**Status:** bounded reference supplier-software-qualified and published on main
at `cec93f8`; birth-fact storage ownership proposed, unresolved. Consumer
adoption remains open. The [publication receipt](../testing/receipts/subject-reference-20261016/publication.json) binds the verified checkpoint.

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

## Associated resources (2026-10-16; proposed consumer model)

A subject reference is the join between a resource and the person it concerns.
Keys are one existing anchor family, not a requirement for a contact and not
proof of every associated fact. The reference must retain the receiving
resident/vault context and actual Gaz book scope. Names and matching birth
dates do not join contacts automatically. Gaz's key lookup returns an iterator:
one matching key is not a guarantee of one local contact record.

A resource keeps its own owner, stable id and revision and names its subject
through an explicit typed association. This is a proposed receiving model,
not a new serialized API in this slice. A contact card, a retained birth-input
record, a Chatelaine address item and a Cleromancy chart can concern the same
subject without copying their content into `SubjectRef` or a public roster.
One resource can concern several subjects, such as a shared household address;
one subject can have several names, addresses or conflicting sourced claims.
A subject link is not authority to read, export or exercise its target.

Existing autofill ownership stays in force: tier-architecture ruling 12 assigns
CXF person-name and address imports to Chatelaine kinds, with all payload
fields sealed by Castellan and exercise through the allowed host paths. This
plan's proposed resident-held biography domain is a possible home for reusable
birth facts, not a replacement for that ruling or a mandate to move every
personal resource into one store. Parsed JSContact Cards preserve unmapped
properties, but those opaque fields are not yet a typed admitted biography.

An associated fact should distinguish what is asserted from who supplied or
attested it: subject, typed predicate/value, source or issuer, evidence,
precision/uncertainty, valid period where relevant, and resource revision.
These are proposed semantics; the data owner chooses the schema and existing
resident admission/disclosure contracts. Signature validation establishes a
particular key's statement; accepting a biography claim needs the relevant
source policy. A private petname remains the book owner's label, distinct
from the subject's self-reported name or a document-derived legal name.

For C8, a reading refers to its subject separately from its actor and retains
the exact authorized birth inputs and calculation revision it used. Later
corrections to an address, birth time or shared contact resource must not rewrite
that historical reading. Contact deletion or lost access remains an unresolved
reference rather than a name-based fallback. Reusable birth storage and the
resource-association envelope still require their own receiving implementation;
only `SubjectRef` and structural lookup are implemented in this supplier slice.

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

- Parent review retains the original implementation commits. Re-ran `cargo test -p dramatis -p gaz --all-features --locked --offline` with Cargo 1.99.0 and explicit Rust/Rustdoc 1.97.1: 7/92 tests and four Gaz doctests pass. The [supplier receipt](../testing/receipts/subject-reference-20261016/qualification.json) binds the exact source and compiled inputs. Added the proposed subject-to-resource association model and preserved the existing Chatelaine autofill ruling.
