# Portable synthetic demo

This package demonstrates Keyhole's historical consented-access fixture baseline:

```text
5490dd418767ddbfe27c1f10bbeb091e315eab68
```

It is a local Go-test demonstration, not an installation or deployment guide. The tests create temporary fixture clients (`acme` and `globex`), endpoint files, identities, tokens, NATS server, SQLite store, relay, gateway, HTTP handlers, MCP client, and agent. Cleanup is owned by Go's test framework. Nothing in this command connects to a configured Keyhole relay, a tailnet, an employer tenant, or a managed endpoint.

## Run

From the repository root:

```sh
scripts/portfolio-demo.sh
```

The wrapper prints the checked-out SHA and runtime environment, then runs four existing aggregate test cases with `-count=1`. It exits at the first failed command and returns that command's nonzero status. Its headings describe the scenario covered by each existing test; they are not seven new independent checks or a simulated user interface.

## What the aggregate cases assert

| Existing case | Demonstrated fixture behavior |
|---|---|
| `TestCrossTenantGate` | A permitted, redacted fixture-log read succeeds; hard-denied, cross-client, cross-device, and cross-technician reads fail. It explicitly ends an access grant, rejects replay, and verifies the reopened audit chain. |
| `TestTechnicianApprovalE2E` | A permitted `app.conf` read succeeds after synthetic technician approval and excluded `secret.txt` read fails. A prepared change waits for approval, an approved rollback restores the prior content, a stale plan preserves a third-party edit, and locking terminates the grants. |
| `TestAuditExportAndVerify` | Fixture audit export verifies before deliberate record tampering and reports the broken chain afterward. |
| `TestRevokeDeviceCutsItOff` | Revoking a synthetic device closes its NATS connection and rejects reconnecting with that device credential. |

The cases exercise the production Go packages in-process. They do not validate a fresh Windows service install, a physical consent window, the current uncommitted diagnostic work, external security review, tenant deployment, or customer use.

## Recorded verification

This package was created and verified on September 14, 2026 with:

```text
OS: Darwin 24.6.0 x86_64
Go: go1.26.0 darwin/amd64
Baseline: 5490dd418767ddbfe27c1f10bbeb091e315eab68
```

The wrapper's four test invocations passed from this isolated checkout. Rerun it before recording or publishing; the SHA and environment printed at runtime identify exactly what was tested.
