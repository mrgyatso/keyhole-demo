# Publication notice

This isolated branch prepares a sanitized historical demonstration package. It is not published and has no configured public remote.

## Provenance

- Source baseline: `5490dd418767ddbfe27c1f10bbeb091e315eab68` (`consent/integration` historical snapshot)
- Demo-only commit: `b94f85a165faf3b158e89fbb333547098a4ed729`
- Publication branch: `publication/keyhole-historical-demo`

The current feature work is intentionally excluded. At package preparation, `consent/signin` was 35 commits ahead of the baseline and had local uncommitted diagnostic changes; the command-runner branch had four commits not in the baseline. The installer commit is contained in the newer sign-in line. None of that work is represented by this package's tests or claims.

## Sanitization performed

This branch removes deployment configuration, installer scripts, operational runbooks, historical acceptance/deployment notes, planning material, research notes, and compiled Windows resource objects that retained historical deployment metadata. It retains only synthetic fixture inputs for the portable demonstration.

The owner selected the MIT License for Zachary Woods's original Keyhole code. The added LICENSE and THIRD-PARTY-NOTICES.md keep that grant distinct from third-party dependency terms.

## Release decisions still required

1. The owner must review this branch's diff and decide whether the historical source may be made public.
2. Newer feature work needs an independent clean-baseline, reconciliation, and acceptance pass before any current-feature publication claim.

Until those decisions are complete, share only the local demo output and these source materials with the owner or reviewers authorized to see them.
