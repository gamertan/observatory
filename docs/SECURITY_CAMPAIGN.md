<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security and recovery campaign

This document maps the current maintainer self-assessment to executable
evidence. It is not an independent audit or a claim that the public preview is
ready. The release commit, packaged binary, browser campaign, capacity run,
and fleet soak must receive separate evidence before the preview tag.

## Current executable evidence

| Boundary | Executable evidence |
| --- | --- |
| Organization isolation and scoped queries | `TestBootstrapSeparatesPlatformAndOrganizationAccess`, `TestTeamsInvitationsRevocationAndBreakGlassRemainOrganizationScoped`, `TestPlanRejectsCrossTenantScopeAndScanBudget`, `TestCredentialScopeCannotBeOverridden` |
| Invitations, teams, revocation, and break-glass audit/expiry | `TestTeamsInvitationsRevocationAndBreakGlassRemainOrganizationScoped` plus the pinned Web Foundations package tests |
| Generated bootstrap credential, forced first-login rotation, and local recovery | `TestAdminBootstrapGeneratesExclusiveOneTimeCredential`, `TestAdminBootstrapSupportsConfinedSystemdCredentials`, `TestAdminHierarchyAndEnrollmentSupportConfinedSystemdCredentials`, `TestAdminUserResetPasswordGeneratesPrivateCredentialAndRevokesSessions`, `TestTemporaryOperatorMustRotatePasswordBeforeUsingApplication`, `TestAPITemporaryOperatorReceivesScopedRotationToken`, plus pinned Web Foundations password-change and atomic recovery tests |
| Token-bound HTML forms with privacy-browser compatibility and cross-site rejection | `TestHTMLLoginUsesTokenWhenBrowserOmitsOrObscuresOriginMetadata`, `TestHTMLLoginFailsClosed`, `TestTemporaryOperatorMustRotatePasswordBeforeUsingApplication`, `TestDashboardManagementIsScopedCSRFProtectedAndExportable`, `TestIncidentRulesEvaluationInboxAndResponseAreScoped` |
| Replay, exact logical-batch acknowledgement, duplicate batches, sequence gaps, enrollment, and source revocation | `TestScopedIngestionDeduplicationAndReplay`, `TestNativeEnvelopeReplayUsesBatchIdentityAndAllowsOverlappingTime`, `TestFramedNativeIngestAcknowledgesExactReplayAndOverlappingTime`, `TestSendAcceptsRealServerBatchDigestRatherThanPrivateSegmentDigest`, `TestRunnerPreservesSpoolOnMismatchedAcknowledgement`, `TestEnrollmentIsScopedExpiringAndSingleUse`, `TestAgentEnrollmentIsSingleUseAndCredentialCanSelfRevoke` |
| Native envelope and compressed or malformed OTLP framing | `TestEnvelopeHeadersRoundTripAndRejectAmbiguity`, `FuzzParseEnvelopeHeaders`, `TestOTLPHTTPIngestionIsAuthenticatedBoundedAndCompressed`, `TestDecodeRejectsMalformedAndNonFiniteData`, `FuzzDecode` |
| Cardinality, timestamp, field, query, scan, memory, and result bounds | `TestBatchRejectsDistinctFieldCardinalityAbuse`, `TestBatchClockSkewAndRetentionWindowsFailClosed`, `TestQueryEnforcesSensitiveAndExecutionBudgets`, `FuzzParse` |
| Secret minimization and safe error output | `TestCaddyCollectorDropsSecretsAndQuery`, `TestRequestLogCollectorUsesWhitelist`, `TestDecodeLogsDropsCredentialsAndPreservesTelemetry`, `TestIngestDoesNotExposeValuesInErrors` |
| Filesystem and interrupted-write boundaries | `TestStorageRejectsSymlinkedSQLiteFilesAndProjectionDirectories`, `TestStateAtomicRoundTripAndSymlinkRefusal`, `TestSpoolRejectsQuotaAndSymlink`, `TestTailerPreservesPartialLineAndRecoversRotation`, `TestInterruptedTemporarySegmentIsIgnoredUntilAtomicCommit` |
| Raw corruption and crash recovery | `TestCommitReadAndCorruption`, `TestRecoveryIndexesRawSegmentMissingFromControlDatabase`, `TestProjectionRebuildFailurePreservesLiveProjection` |
| Complete projection reconstruction | `TestProjectionRebuildRestoresRawTruthAndActivatedDescriptorsAtomically`, `TestProjectionRebuildRejectsUnknownOrganization`, `TestProjectionRebuildRefusesSymlinkProjectionOrSidecar` |
| Migration locking and schema fixtures | `TestProcessLockSeparatesLiveServerFromOfflineMigration`, `TestOfflineMigrationRefusesLiveDataDirectory`, `TestControlSchemaFourMigratesToIncidentSchema`, `TestControlSchemaFiveMigratesToPushSchema` |
| PWA, SSE, incident scope, and generic push content | `TestManifestAndServiceWorkerUseExactContentAddressedShell`, `TestLiveRefreshStreamIsAuthorizedAndCarriesNoTelemetry`, `TestIncidentRulesEvaluationInboxAndResponseAreScoped`, `TestSenderUsesEncryptedGenericPayloadAndValidVAPID` |
| Tend input and non-authoritative deployment evidence | `TestTendCollectorIsStrict`, `FuzzTendCollector`; producer activation/rollback failure injection remains authoritative in Tend's own repository |

The migration fixtures cover every internal control schema that predates this
candidate and can reach its current schema. Observatory has not published a
preview, so no public-version migration claim exists yet. Each future public
preview must retain a fixture and a raw-projection rebuild path.

## Reproduction

The ordinary verifier pins Go and Hime-san, checks generated-source freshness
and no-op determinism, then runs tests, the race detector, vet, a trimmed
build, and the production dependency boundary:

```sh
GOCACHE=/tmp/observatory-go-cache ./scripts/verify.sh
```

The bounded adversarial campaign adds query, OTLP, and Tend-event fuzzing and
reruns the security-critical packages under the race detector:

```sh
OBSERVATORY_FUZZ_TIME=30s \
GOCACHE=/tmp/observatory-go-cache \
./scripts/security-campaign.sh
```

On August 17, 2026, a 10-second-per-target development run completed without
an invariant failure: approximately 2.45 million query-parser cases, 670,000
OTLP cases, and 166,000 strict Tend-event cases, followed by the uncached race
matrix. Counts are observations from one run, not minimum performance claims.

Trusted Gitea assurance run 232 then exercised source commit
`14125387d13947eb4a523e95c2e441ff89abcc1a` (tree
`f378872450054e7ff6f5499c61a5db0e4a3d3da7`) with the pinned Go 1.26.6
toolchain and `govulncheck` v1.6.0. It completed 1,092,559 query-parser,
398,595 OTLP-decoder, and 324,020 Tend-event fuzz executions in three separate
30-second targets, then passed the uncached security-package race matrix and
the ordinary deterministic verifier. The checkout remained unchanged.

The same scan reported zero reachable vulnerabilities and zero
vulnerabilities in imported packages. It also reported GO-2026-5932 in the
required `golang.org/x/crypto` module because its legacy `openpgp` package is
unmaintained. Observatory and its Web Foundations dependency do not import
that package, and the advisory has no fixed module version. This is a recorded
dependency boundary, not a claim that the module-only advisory was repaired.

The resource-limited ingestion, query, outage-replay, and retention gate is
defined separately in [`CAPACITY.md`](CAPACITY.md). Its short development mode
is suitable for implementation feedback; only the exact one-hour release mode
can close the capacity item below.

## Open release evidence

- Exercise one granted browser-vendor Web Push delivery and OS notification
  activation in a headed supported browser. The networkless Chromium campaign
  below proves the application and worker boundaries without contacting a push
  relay or depending on a desktop notification service.
- Complete the specified 4-vCPU/8-GiB capacity campaign, outage replay,
  retention, compaction, and concurrent-organization workloads. The
  August 17 constrained run passed its one-hour 2,000-observation/second
  sustain boundary but missed the 10,000-observation/second burst boundary;
  [`CAPACITY.md`](CAPACITY.md) records the measured result and remaining work.
- Complete the medium-fleet dogfood soak. Observatory's first real Tend
  activation, rollback, and identical-artifact redeployment passed on
  August 17; [`DEPLOYMENT.md`](DEPLOYMENT.md) records that bounded result.
- Re-run this campaign against the exact packaged release commit and record
  its immutable artifact digest, SBOM, checksum, and signature.

## Real-browser campaign

`scripts/browser-campaign.sh` builds a build-tagged, disposable HTTPS fixture
and drives Chromium through pinned Playwright 1.62.1. The approved Linux image
is `mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e`.
The fixture and browser use loopback only. The campaign rejects every HTTP
request to another origin and verifies manifest installability, the public
offline shell, explicit private-inbox caching and sign-out deletion, SSE
reconnection, app badging, generic notification content and activation,
keyboard entry, landmarks, forced colors, reduced motion, and 320-pixel
overflow.

On August 17, 2026, the campaign completed twice in pinned headless Chromium
inside a disposable, networkless Linux container limited to four CPUs and
8 GiB. Both runs reported every evidence field true and zero external HTTP
requests. They exercised a real service worker, cache storage, EventSource,
session, incident inbox, application badge, and the production push and
notification-click handlers. Headless Chromium denied the intentional
user-triggered notification permission request, so the worker's fixed-shape
push event and activation path were invoked directly; the prohibited OS focus
side effect was replaced with an in-worker client test double. This proves the
payload and activation contract, not end-to-end browser-vendor delivery. The
exact npm lockfile audit reported zero known vulnerabilities at all severities.

The disposable fixture uses a one-hour self-signed `localhost` certificate and
passes only its ephemeral SHA-256 subject-public-key fingerprint to Chromium's
SPKI allowlist. Chromium serializes `Origin: null` on form submissions under
that synthetic certificate while Fetch Metadata still reports `same-origin`.
The fixture does not rewrite those headers: the campaign exercises the same
token-bound HTML form policy used in production and asserts the observed
metadata. The token remains mandatory, and explicit cross-site metadata still
fails closed. This is not a general TLS-origin acceptance test.

To test native EventSource recovery deterministically, the build-tagged
fixture cancels the real authenticated `/app/events` request after 1.25
seconds. The browser must reconnect and receive a later generic refresh event.
The production handler, authorization, event format, and connection lifetime
are not changed.

Install the exact development dependency without downloading a browser when a
pinned Playwright container supplies Chromium:

```sh
cd test/browser
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --ignore-scripts
cd ../..
./scripts/browser-campaign.sh
```

The resulting JSON contains pass/fail booleans and no machine, user, token,
organization, incident, path, or telemetry identifiers. A development pass is
not release evidence until repeated against the packaged release commit and
the pinned container digest is recorded.
