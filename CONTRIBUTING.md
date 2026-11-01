# Contributing

Thanks for helping keep these advisories accurate. The goal is to make each
record useful to package users and maintainers, not to label something
malicious just because it looks unusual.

## Report a correction or a new version

Open an issue using the Report an advisory update form. Include the advisory
ID, the package and exact version, what you think needs changing, and links to
the evidence. For a patched-version proposal, explain how the exact release
fixes the vulnerability described by that advisory.

Please don't post API keys, private package contents, personal data, or other
secrets in an issue.

## Send a pull request

Pull requests are welcome for corrections, references, affected-version
updates, patched-version proposals, and documentation improvements. Use the
pull request template and keep changes focused.

For advisory changes:

- Keep the existing AUTH ID when the underlying vulnerability is the same.
- Create a new advisory when the package has a different vulnerability.
- List exact affected releases in affected.versions.
- Put proposed fixed releases in affected.patched_versions.
- Add a separate affected.version_details statement for every release you add.
- Link to evidence for the exact version. A package README or project description
  is not evidence that code is malicious.
- Leave database_specific.intent_assessment as undetermined.
- Leave generated or changed review state as PENDING. Do not approve your own
  contribution.

A clean scan alone is not enough to add a patched version. The PR should show
what changed in the release and why that change addresses the same
vulnerability.

## What happens after submission

A maintainer checks the package, version-specific evidence, external sources,
and proposed classifications. Merging a reviewed advisory change is the
approval step. Automated scans and AI-generated text are drafts; they do not
publish an advisory on their own.

Published advisory reports are generated from the reviewed JSON records.
Please don't hand-edit generated reports unless a maintainer asks you to.

## Automated scans

The scheduled scanners use Gemini for static analysis and Firecrawl for web
search. The repository needs the GEMINI_API_KEY and FIRECRAWL_API_KEY GitHub
Actions secrets. Add them under Settings, Secrets and variables, Actions.
Never put either key in a commit, issue, workflow output, or report.

Package code is downloaded and inspected statically. The scanners must not
install or execute the packages they review.
