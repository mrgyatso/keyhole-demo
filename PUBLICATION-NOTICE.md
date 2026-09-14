# Publication notice

This repository preserves a sanitized historical demonstration snapshot of the experimental Keyhole project. Its public destination is [mrgyatso/keyhole-demo](https://github.com/mrgyatso/keyhole-demo).

## Provenance

- Source baseline: `5490dd418767ddbfe27c1f10bbeb091e315eab68` (`consent/integration` historical snapshot)
- Demo-only commit: `b94f85a165faf3b158e89fbb333547098a4ed729`
- The publication was prepared in an isolated branch and exported into a new history. Original private commits, branches and working trees remain preserved separately.

The current feature work is intentionally excluded. At package preparation, `consent/signin` was 35 commits ahead of the baseline and had local uncommitted diagnostic changes; the command-runner branch had four commits not in the baseline. The installer commit is contained in the newer sign-in line. None of that work is represented by this package's tests or claims.

## Sanitization performed

This branch removes deployment configuration, installer scripts, operational runbooks, historical acceptance/deployment notes, planning material, research notes, and compiled Windows resource objects that retained historical deployment metadata. It retains only synthetic fixture inputs for the portable demonstration.

The owner selected the MIT License for Zachary Woods's original Keyhole code. The added LICENSE and THIRD-PARTY-NOTICES.md keep that grant distinct from third-party dependency terms.

## Snapshot lifecycle

The owner authorized publication and selected MIT for the original source. This historical demonstration snapshot is frozen; it has no maintenance or support commitment. The Keyhole project has newer work outside this snapshot, so this notice does not declare that project ended.

Newer feature work needs its own selected baseline and acceptance results before it can be represented as a current release. The tests and recorded transcript here apply to the stated historical fixture only.
