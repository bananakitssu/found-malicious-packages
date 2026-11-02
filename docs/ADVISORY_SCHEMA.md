# Advisory format

Authtics Advisories uses schema version 1.1. The JSON schema is in
[schemas/advisory-1.1.schema.json](../schemas/advisory-1.1.schema.json).

## What changed in 1.1

Each affected package entry now has three version fields:

- versions lists the exact releases considered affected.
- patched_versions lists exact releases proposed as fixed for this advisory.
- version_details gives each release its own statement and status.

A release must not appear in both versions and patched_versions. Every entry in
version_details must agree with the matching list. Statements must be specific
to the release they describe. Do not copy evidence from one release to another
or assume that every release in a package's history behaves the same way.

A patched version is a proposal, not a guarantee. The scan must compare that
exact release with the same vulnerability and explain what changed. A clean
scan by itself is not proof that a vulnerability was fixed. All additions to
either version list return to human review.

## Intent and wording

An advisory records behavior and evidence. It does not establish why an author
wrote the code or what they intended to do. The database_specific field must
therefore keep intent_assessment set to undetermined.

Describe what the code does and what the evidence shows. Avoid statements
about an author's motive unless a reliable source directly supports the
attribution. Keep an external source's allegation separate from observed
package behavior.

## Review state

New findings and changes to existing findings start with review.status set to
PENDING and human_review_required set to true. A scan never approves its own
work. Maintainers review the diff, version statements, sources, and proposed
CWE classifications before changing the review state.

When an advisory is updated, the existing ID and original published date stay
the same. The modified date changes. A genuinely different vulnerability
gets a different advisory ID, even when it affects the same package.

## Migrating older records

Records previously stored as schema 1.0 were migrated to 1.1. Their existing
affected version lists were retained. Since 1.0 did not keep a separate
statement for each version, migrated records include a note saying that
version-specific evidence was not preserved. That note should not be mistaken
for new evidence about an individual release.
