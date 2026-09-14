# Captured portable-demo transcript

This is the unedited terminal output captured on September 14, 2026 from the historical demonstration branch at 9fa45330f3df4c09734a226fc4440b487ce670af. The fixture source baseline remains 5490dd418767ddbfe27c1f10bbeb091e315eab68; the wrapper itself was added by b94f85a165faf3b158e89fbb333547098a4ed729.

    $ scripts/portfolio-demo.sh
    Keyhole portable synthetic demo
    baseline checkout: 9fa45330f3df4c09734a226fc4440b487ce670af
    environment: go version go1.26.0 darwin/amd64
    This runs local Go fixtures only; it does not install an agent or contact a configured relay.

    == Aggregate fixture: tenant/grant isolation, permitted and denied reads, access end, audit verification ==
    === RUN   TestCrossTenantGate
    --- PASS: TestCrossTenantGate (0.61s)
    PASS
    ok  	github.com/mrgyatso/keyhole/e2e	1.473s

    == Aggregate fixture: technician-approved change, rollback, stale-plan rejection, grant lock ==
    === RUN   TestTechnicianApprovalE2E
    --- PASS: TestTechnicianApprovalE2E (1.07s)
    PASS
    ok  	github.com/mrgyatso/keyhole/e2e	1.813s

    == Aggregate fixture: audit export, hash-chain verification, and tamper detection ==
    === RUN   TestAuditExportAndVerify
    === RUN   TestAuditExportAndVerify/jsonl
    === RUN   TestAuditExportAndVerify/report_formats_come_from_Config.Reports
    === RUN   TestAuditExportAndVerify/verify
    === RUN   TestAuditExportAndVerify/unknown_client
    --- PASS: TestAuditExportAndVerify (0.11s)
        --- PASS: TestAuditExportAndVerify/jsonl (0.00s)
        --- PASS: TestAuditExportAndVerify/report_formats_come_from_Config.Reports (0.00s)
        --- PASS: TestAuditExportAndVerify/verify (0.00s)
        --- PASS: TestAuditExportAndVerify/unknown_client (0.00s)
    PASS
    ok  	github.com/mrgyatso/keyhole/internal/relay	0.465s

    == Aggregate fixture: device revocation disconnects and rejects reconnect ==
    === RUN   TestRevokeDeviceCutsItOff
    nats: authentication revoked on connection [8]
    --- PASS: TestRevokeDeviceCutsItOff (0.07s)
    PASS
    ok  	github.com/mrgyatso/keyhole/internal/relay	0.473s

    All aggregate fixture cases passed.

The revocation log line is emitted by the local NATS fixture while the existing revocation assertion runs. The test output is evidence for this synthetic run only.

## Source assertions

- [Tenant/grant isolation and audit verification](../e2e/isolation_test.go#L74)
- [Technician-approved change, rollback, and stale-plan assertions](../e2e/approval_test.go#L285)
- [Audit export and tamper-detection assertions](../internal/relay/export_test.go#L18)
- [Revocation disconnect and reconnect-refusal assertions](../internal/relay/conns_test.go#L125)
