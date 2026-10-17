# Subject references for saved natal readings

**Date:** 2026-10-16

**Status:** bounded reference supplier-software-qualified and published on main
at `cec93f8`. Reusable birth facts and subject/resource associations are now
explicitly authorized and implemented locally for review; resident persistence,
admission and consumer adoption remain parent-owned qualification work. The
[publication receipt](../testing/receipts/subject-reference-20261016/publication.json)
binds the unchanged original reference checkpoint, not the new contracts.

**Source base:** Dramatis `2f27f1a939aa2e046b78f7db18dcd8f81e0d7c59`, fetched
`origin/main`. Deciders: maintainer and receiving Cleromancy/resident owners.

**Additive contract base (2026-10-16):** clean published main
`36ca194e5d48c66ae44af9530cc12c9f6a05b0be`, matching fetched `origin/main`.

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

Dramatis's original published slice supplies **a reusable subject reference**:
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
| Resident-held personal-data domain, referenced by identity | Authorized: plain reusable facts and subject/resource vocabulary live in Dramatis; the resident personal-facts domain owns durable revisions, admission, access and lifecycle. Parent owns its implementation and receiving proof. |

The ownership decision authorizes plain contracts here, **not an assertion that
this repository supplies the resident service**. No birth storage, permissions
model or credential-release route is implemented here.
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
2. The data owner must preserve original civil date, calendar and
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

## Associated resources (2026-10-16; authorized plain contract)

A subject reference is the join between a resource and the person it concerns.
Keys are one existing anchor family, not a requirement for a contact and not
proof of every associated fact. The reference must retain the receiving
resident/vault context and actual Gaz book scope. Names and matching birth
dates do not join contacts automatically. Gaz's key lookup returns an iterator:
one matching key is not a guarantee of one local contact record.

A resource keeps its own owner, stable id and revision and names its subject
through an explicit typed association, now supplied by `dramatis::resources`.
A contact card, a retained birth-input
record, a Chatelaine address item and a Cleromancy chart can concern the same
subject without copying their content into `SubjectRef` or a public roster.
One resource can concern several subjects, such as a shared household address;
one subject can have several names, addresses or conflicting sourced claims.
A subject link is not authority to read, export or exercise its target.

Existing autofill ownership stays in force: tier-architecture ruling 12 assigns
CXF person-name and address imports to Chatelaine kinds, with all payload
fields sealed by Castellan and exercise through the allowed host paths. This
plan's resident-held personal-facts domain owns reusable birth facts, not a
replacement for that ruling or a mandate to move every
personal resource into one store. Parsed JSContact Cards preserve unmapped
properties, but those opaque fields are not yet a typed admitted biography.

An associated fact should distinguish what is asserted from who supplied or
attested it: subject, typed predicate/value, source or issuer, evidence,
precision/uncertainty, valid period where relevant, and resource revision.
The first birth-facts schema below carries the bounded fields required for C8;
richer attestations and valid periods remain outside it. The data owner applies
existing resident admission/disclosure contracts. Signature validation establishes a
particular key's statement; accepting a biography claim needs the relevant
source policy. A private petname remains the book owner's label, distinct
from the subject's self-reported name or a document-derived legal name.

For C8, a reading refers to its subject separately from its actor and retains
the exact authorized birth inputs and calculation revision it used. Later
corrections to an address, birth time or shared contact resource must not rewrite
that historical reading. Contact deletion or lost access remains an unresolved
reference rather than a name-based fallback. Reusable birth storage and the
resource-association envelope still require their own receiving implementation.

## Reusable facts and association API (2026-10-16)

The new modules are additive. All fields are public; checked constructors return
`Result<_, ValidationError>`, and each data type exposes `validate()`. The same
plain error type is available as `birth::ValidationError` and
`resources::ValidationError`, with static `field` and `reason` strings.
Deserialization calls the validators, rejects unknown fields, and refuses
unsupported schemas. Public-field mutation can temporarily make an invalid
value: callers **must revalidate before serialization, use or admission**.
Serde serialization itself does not imply validity, authenticity or authority.

- `resources::ResourceRef { domain, id, revision }` requires non-whitespace
  strings without rewriting their spelling. It names an exact revision, never
  an implicit latest. `ResourceRef::new` accepts those three `String`s.
- `SubjectResourceAssociation { schema, subject, resource, relationship }`
  requires `schema == SUBJECT_RESOURCE_ASSOCIATION_SCHEMA`, exactly
  `dramatis.subject-resource-association/v1`. Its constructor takes subject,
  resource and `SubjectResourceRelationship`; `About` is the first and only
  relationship. Several associations may concern the same resource; there is
  no deduplication, key uniqueness claim, name matching or permission grant.
  `SubjectResourceAssociation::about(subject, resource) -> Self` is the requested
  infallible convenience: it sets the valid schema and About relationship but
  still requires `validate()` for caller-supplied mutable nested resource data.
- `birth::BirthFacts { schema, subject, date, time, place, timezone, source }`
  requires `schema == BIRTH_FACTS_SCHEMA`, exactly `dramatis.birth-facts/v1`.
  Its constructor takes all six non-schema fields in that order and sets the
  schema. Subject is mandatory and keeps the existing `SubjectRef` semantics.
- `CivilDate { year: i32, month: u8, day: u8 }` is proleptic Gregorian with
  years 1..=9999, including century leap-year checks. This first schema cannot
  represent a non-Gregorian source date directly; a receiving owner must retain
  its original-calendar evidence separately when converting it for this schema.
- `BirthTime::Unknown`, `Known { hour, minute, second }`, and
  `Approximate { hour, minute, second, uncertainty_seconds }` preserve civil
  clock assertions. Hour is 0..=23, minute/second 0..=59; leap-second input
  refuses. Approximation has a positive radius of 1..=86400 seconds on each
  side, potentially crossing local date boundaries, not a resolved UTC range.
  Constructors are `BirthTime::known` and `BirthTime::approximate`; Unknown
  never gains a clock value or a default instant.
- Optional `BirthPlace { label, latitude_microdegrees, longitude_microdegrees,
  precision }` requires non-whitespace label/precision and paired coordinates
  or neither coordinate. Latitude bounds are ±90,000,000; longitude bounds
  ±180,000,000, both inclusive. Optional `timezone: String` preserves supplied
  IANA input text and checks only nonemptiness. The parent validates identifiers
  and historical rules; no timezone database is linked here.
- `FactSource { label, reference: Option<String> }` requires a non-whitespace
  label and any provided reference. Labels/references do not verify truth or
  identify a cryptographic issuer. Constructors for date, place and source
  take their public fields in declaration order.

JSON has fixed declaration-order supplier fixtures, explicit external enum tags
and explicit nulls for absent optional values (missing optional fields also
deserialize as absent). This is stable Serde output, not a canonical hashing or
signature format. Postcard roundtrips preserve the same fields and variant
order. Original `SubjectRef` source, binary fixtures and tests remain untouched.

The resident must bind both envelopes to its context and verify any association
against the referenced resource's actual subject and exact revision; these plain
types do not fetch a target or compare independently supplied envelopes. The
resident personal-facts domain owns durable fact revisions and admission.
Historical zone resolution, candidate offsets, UTC and calculation provenance
belong to derived resources that refer to the original fact revision. Extra
derived fields in `BirthFacts` refuse. This contract uses no clock, resolver,
network, storage, cryptographic verifier or new permission system. Parent owns
Mere receiving persistence/admission and Cleromancy numerical/time/UI wiring.
Djinn has no existing live contact-book wiring in this receiving slice: parent
will hold scoped local Gaz contact resources in the shared personal-facts
domain, reusing Gaz types, alongside existing profile references. This does not
authorize an app-local directory or add contact custody to the supplier lane.

## Phases and validation

- Reference slice: done when existing types remain unchanged, the additive
  contract round-trips JSON/Postcard and refuses malformed references, wrong
  scopes and missing records. Locally implemented; test evidence below.
- Plain birth/resource contracts: implemented locally for review. Done when
  nested validation, strict schema/field refusals and stable Serde tests pass,
  while published subject types, receipts and Chatelaine ruling 12 stay intact.
- Resident biography ownership: authorized as the personal-facts data domain;
  parent implementation and real receiving qualification remain open.
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

- Authorized reusable-facts extension: added `birth`, `resources`, a private
  shared deserialization validator and focused tests on base `36ca194`.
  Checked constructors, public-field revalidation and strict JSON/Postcard load
  refuse invalid Gregorian dates, clocks, approximation bounds, unpaired or
  out-of-range coordinates, empty supplied text, unknown schemas/fields and
  attempted derived UTC additions. Fixed fixtures preserve all time variants
  and source inputs; a complete Gregorian cycle has 146097 valid dates.
  Associations preserve several subjects and repeated links to one resource.
  The original seven subject tests, binary fixtures and publication receipts
  remain unchanged. Parent-requested `about(subject, resource) -> Self` supplies
  valid schema/relationship without bypassing nested `validate()` checks.
- Final focused validation: `cargo test -p dramatis --locked --offline` on
  Rust/Cargo 1.99.0 and `cargo +1.97.1 test -p dramatis --locked --offline`
  both pass 24 tests (17 new and seven unchanged subject tests). Focused
  Rustfmt and whitespace checks pass. No dependencies, lock entries, existing
  receipts or published subject wire formats changed. Supplier software checks
  do not qualify resident persistence/admission, numerical/time conversion,
  consumer replay, native UI or fresh-process receiving behavior.
