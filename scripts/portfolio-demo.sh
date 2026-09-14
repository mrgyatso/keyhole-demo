#!/usr/bin/env sh
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

printf '%s\n' 'Keyhole portable synthetic demo'
printf 'baseline checkout: '
git rev-parse HEAD
printf 'environment: '
go version
printf '%s\n' 'This runs local Go fixtures only; it does not install an agent or contact a configured relay.'

run_case() {
  label=$1
  shift
  printf '\n== %s ==\n' "$label"
  "$@"
}

run_case 'Aggregate fixture: tenant/grant isolation, permitted and denied reads, access end, audit verification' \
  go test -count=1 -v ./e2e -run '^TestCrossTenantGate$'
run_case 'Aggregate fixture: technician-approved change, rollback, stale-plan rejection, grant lock' \
  go test -count=1 -v ./e2e -run '^TestTechnicianApprovalE2E$'
run_case 'Aggregate fixture: audit export, hash-chain verification, and tamper detection' \
  go test -count=1 -v ./internal/relay -run '^TestAuditExportAndVerify$'
run_case 'Aggregate fixture: device revocation disconnects and rejects reconnect' \
  go test -count=1 -v ./internal/relay -run '^TestRevokeDeviceCutsItOff$'

printf '\n%s\n' 'All aggregate fixture cases passed.'
