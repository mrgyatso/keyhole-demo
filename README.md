# Keyhole

Keyhole is an experimental project for consented, policy-scoped and auditable support access to managed endpoints. This package is a historical demonstration snapshot that exercises the core access and change-control paths without accessing private infrastructure or a managed endpoint.

## Status and scope

This source package is pinned to the historical consented-access baseline `5490dd418767ddbfe27c1f10bbeb091e315eab68`, plus the two-file portable-demo documentation commit `b94f85a165faf3b158e89fbb333547098a4ed729`. It is evidence of that snapshot, not a statement about the newer sign-in, installer, command-runner, or diagnostic work.

The package intentionally excludes deployment files, operating runbooks, historical acceptance notes, and research notes. It is **not** an installer, deployment guide, or production-readiness claim. The real project architecture uses managed endpoint services and a persistent relay; those operational components are outside this portable demo.

## Demonstration

With Go 1.26 installed, run:

```sh
scripts/portfolio-demo.sh
```

The command invokes four existing Go test cases. They create temporary fixture clients, endpoint files, identities, tokens, NATS, SQLite, relay, gateway, HTTP handlers, MCP client, and agent in-process. The command has no live-target arguments and must not be substituted with agent installation, relay initialization, enrollment, or deployment commands.

The cases collectively cover:

- permitted and denied fixture reads, tenant/grant isolation, access end, and audit-chain verification;
- a reviewed change, separately reviewed rollback, stale-plan rejection, and lock-based access revocation;
- audit-export tamper detection; and
- revoked-device disconnect and refused reconnect.

Read [the portable demo guide](docs/PORTABLE-DEMO.md), [captured terminal transcript](docs/DEMO-TRANSCRIPT.md), and [architecture overview](docs/ARCHITECTURE.md) before running it. Each label in the wrapper refers to an aggregate existing test case, rather than a new independent check or a user-interface simulation.

## Source and publication boundary

This repository contains Go source and tests needed to inspect the historical fixture. It deliberately omits deployment configuration and all real operational data. Test values are synthetic and must remain synthetic if this package is redistributed.

The original Keyhole source is available under the [MIT License](LICENSE). See [third-party notices](THIRD-PARTY-NOTICES.md) and [the publication notice](PUBLICATION-NOTICE.md) for scope and provenance.
