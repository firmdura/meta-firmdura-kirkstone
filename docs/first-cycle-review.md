# First delivery cycle measurement and operating review

This report reconciles the committed run records under [`evidence/`](../evidence/)
and durable timing ledgers into measured operating data for the first public
reference release
([`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0)).
Machine-readable per-phase figures and reconciliation checks are recorded in
[`evidence/20261118-sti117-cycle-review/run.json`](../evidence/20261118-sti117-cycle-review/run.json).

This document reports measured observations from a single reference case. It is
not a service-level commitment, compatibility guarantee, cost-savings claim, or
proof of commercial demand.

## Timeline and milestone dates

| Milestone | Recorded UTC timestamp | Primary artifact / record |
|---|---|---|
| Upstream `CVE-2026-19773` NVD entry last modified (`Awaiting Analysis`) | `2026-09-18T19:10:46Z` | [ZDI-26-590](https://www.zerodayinitiative.com/advisories/ZDI-26-590/), [upstream fix `824151862f`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b) |
| Upstream OSV `CVE-2026-19773` record modified (`GIT` range only) | `2026-10-28T10:50:35Z` | [`docs/scanner.md`](scanner.md) |
| Bootstrap & locked-layer parse started | `2026-11-17T20:59:10Z` | [`evidence/20261117-sti107-bootstrap/run.json`](../evidence/20261117-sti107-bootstrap/run.json) |
| Cold clean `baseline` image build & QEMU smoke completed | `2026-11-18T00:24:25Z` | [`evidence/20261117-sti108-baseline/run.json`](../evidence/20261117-sti108-baseline/run.json) |
| Target `CVE-2026-19773` `qemuarm64` reproduction completed | `2026-11-18T11:50:49Z` | [`evidence/20261118-sti109-reproduction/run.json`](../evidence/20261118-sti109-reproduction/run.json) |
| Paired `baseline`/`patched` repair & regression freeze completed | `2026-11-18T12:49:29Z` | [`evidence/20261118-sti110-paired-validation/run.json`](../evidence/20261118-sti110-paired-validation/run.json) |
| Evaluation, corresponding-source & licence bundles packaged | `2026-11-18T13:52:44Z` | [`evidence/20261118-sti112-bundles/run.json`](../evidence/20261118-sti112-bundles/run.json) |
| Trusted GitHub Actions OIDC fixture smoke verified | `2026-11-18T14:04:03Z` | [`evidence/20261118-sti111-oidc-fixture/run.json`](../evidence/20261118-sti111-oidc-fixture/run.json) |
| Upstream contribution [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283) submitted | `2026-11-18T14:13:01Z` | [`evidence/20261118-sti114-contribution/run.json`](../evidence/20261118-sti114-contribution/run.json) |
| Dual-track scanner & OpenVEX positive/negative controls verified | `2026-11-18T15:13:06Z` | [`evidence/20261118-sti113-openvex/run.json`](../evidence/20261118-sti113-openvex/run.json) |
| Independent clean-volume source rebuild & candidate replay completed | `2026-11-18T16:30:59Z` | [`evidence/20261118-sti115-replay/run.json`](../evidence/20261118-sti115-replay/run.json) |
| Keyless-Cosign-signed GitHub Release [`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0) published & verified | `2026-11-18T18:52:09Z` | [`evidence/20261118-sti116-release/run.json`](../evidence/20261118-sti116-release/run.json) |

Total end-to-end calendar wall span from initial bootstrap (`2026-11-17T20:59:10Z`)
through verified public release (`2026-11-18T18:52:09Z`) was **`78,779.44 s`
(`21.883 h`)**, including an unworked overnight interval (`00:24Z`–`07:14Z`) and
explicit human-approval waiting windows.

## Phase breakdown: active session time, build durations, and unknowns

Active figures below measure **prospectively bracketed AI assistant-session
active wall time** (excluding paused command, build, transfer, and human-review
waits), **not** human engineering labor hours. Direct human reviewer effort
(code review, environment configuration, and release approvals) was not
stopwatch-instrumented and remains explicitly `null` (unknown) rather than
estimated.

| Phase | Run record | Active assistant session (s) | Paused wait / command wait (s) | BitBake image build (s) | Notes & explicit unknowns |
|---|---|---:|---:|---:|---|
| Applicability, bootstrap & container setup | [`20261117-sti107-bootstrap`](../evidence/20261117-sti107-bootstrap/run.json) | `null` (uninstrumented) | `293.31` (cmd sum) | `0.00` | `2,427` parsed recipes, `4,921` dry-run tasks; active session not metered |
| Initial cold clean `baseline` build & boot | [`20261117-sti108-baseline`](../evidence/20261117-sti108-baseline/run.json) | `null` (uninstrumented) | `10,998.59` (cmd sum) | **`5,366.71`** | `4,921` tasks from empty `downloads`/`sstate`; `15.46 s` QEMU check |
| Baseline archive/inventory handoff audit | [`20261118-sti108-handoff`](../evidence/20261118-sti108-handoff/run.json) | `221.85` | `63.65` | `0.00` | Verified `16,851` files + `9,618` symlinks in `deploy.tar` |
| Keyless signing workflow & verifier prep | [`20261118-sti111-keyless-signing`](../evidence/20261118-sti111-keyless-signing/run.json) | `1,022.46` (`919.93 + 102.53`) | `16.80` | `0.00` | Ran concurrently (`07:32Z`–`08:21Z`) in isolated worktree |
| SPDX 2.2 consolidator & feed preflight | [`20261118-sti119-scanner-preflight`](../evidence/20261118-sti119-scanner-preflight/run.json) | `3,078.74` | `78.49` | `0.00` | Ran concurrently (`08:34Z`–`09:27Z`); `179` SPDX docs -> `39` target pkgs |
| Target `CVE-2026-19773` harness & reproduction | [`20261118-sti109-reproduction`](../evidence/20261118-sti109-reproduction/run.json) | `null` (`15,817.53` upper-bound span) | `110.73` | **`30.06`** | Span (`07:25Z`–`11:50Z`) includes concurrent workers + `09:22Z`–`10:33Z` idle interruption; excluded from strict active sum |
| Scoped `patched` layer, regressions & pair freeze | [`20261118-sti110-paired-validation`](../evidence/20261118-sti110-paired-validation/run.json) | `3,005.16` | `365.45` | **`122.98`** (`7.99 + 114.99`) | Paired `baseline`/`patched` QEMU (`15.03 s` + `15.22 s`) + incomplete-fix controls |
| QEMU evaluation, source & licence bundles | [`20261118-sti112-bundles`](../evidence/20261118-sti112-bundles/run.json) | `2,494.64` | `81.31` | `0.00` | Packaged `436.65 MB` source + `251 KB` licences + standalone QEMU checks |
| Upstream `meta-lts-collab` PR `#283` | [`20261118-sti114-contribution`](../evidence/20261118-sti114-contribution/run.json) | `3,750.59` | `42.70` | `0.00` | Ran concurrently (`13:09Z`–`14:13Z`) with bundle packaging & OIDC fixture |
| Trusted GitHub OIDC `kind=fixture` verification | [`20261118-sti111-oidc-fixture`](../evidence/20261118-sti111-oidc-fixture/run.json) | `552.88` | `0.00` (`15.36` cmd) | `0.00` | Verified Actions run `44306456937` + `7` Cosign negative controls |
| Dual-track OSV Git provenance & aux CPE test DB | [`20261118-sti119-dual-track`](../evidence/20261118-sti119-dual-track/run.json) | `2,374.20` | `56.62` | `0.00` | Offline OSV source/patch detector + `xxh64`-verified isolated SQLite fixture |
| Artifact-scoped OpenVEX & `8`-scan Grype matrix | [`20261118-sti113-openvex`](../evidence/20261118-sti113-openvex/run.json) | `905.63` | `437.42` | `0.00` | Positive (`3 -> 0`) + mandatory negative (`3` kept on `baseline`) controls |
| Independent clean-volume rebuild & candidate replay | [`20261118-sti115-replay`](../evidence/20261118-sti115-replay/run.json) | `3,110.31` | `706.37` | **`306.65`** (`155.53 + 151.12`) | Fresh layer clones, `0` target sstate/downloads, QEMU (`78.95 s`), `8` Grype scans |
| Release assembly, OIDC signing & public checks | [`20261118-sti116-release`](../evidence/20261118-sti116-release/run.json) | `2,582.52` | `6,172.66` | `0.00` | Includes workflow correction (`stage-candidate.yml`) + public HTTPS & QEMU checks |

### Reconciled totals (distinguishing parallel streams from calendar time)

- **Cumulative active assistant-session time across the `11` strictly metered runs**:
  **`23,098.980 s` (`6.416 h`)** (excludes the `2` uninstrumented `2026-11-17`
  runs and the `15,817.535 s` upper-bound `20261118-sti109-reproduction` span).
- **Non-overlapping calendar active time across those `11` strictly metered runs**:
  deducting the `3,047.519 s` (`0.847 h`) parallel overlap during
  `13:09:48Z`–`14:04:03Z` (where `20261118-sti112-bundles` and
  `20261118-sti111-oidc-fixture` executed concurrently with
  `20261118-sti114-contribution`) yields **`20,051.461 s` (`5.570 h`)** of
  non-double-counted active calendar time.
- **Total BitBake image build time (`6` builds)**: **`5,826.392 s` (`1.618 h`)**
  (`92.1%` spent in the single initial cold build `5,366.709 s`; subsequent
  warm-base-sstate builds took `114.99 s`–`155.53 s`).
- **Explicitly paused waiting time on `2026-11-18`**: **`8,132.190 s` (`2.259 h`)**,
  of which `6,172.655 s` (`1.715 h`) was human release-approval waiting and
  `477 MB` release-asset upload/download transfers.

## Builder resources, storage, and infrastructure cost

- **Builder compute**: Dedicated local Colima Linux ARM64 VM (`firmdura-kirkstone`,
  Ubuntu 24.04 LTS, `4` vCPUs, `8 GiB` RAM, `55 GiB` data disk, `10 GiB` root
  disk) on an Apple Silicon control host (`95 GiB` free host disk).
- **Container & volume storage**: `2` pinned container images (`1.582 GB`:
  `ghcr.io/siemens/kas/kas:4.8` and `anchore/grype:0.122.0`) and `7` local
  Docker volumes totaling **`39.84 GB`** (`firmdura-kirkstone-baseline` `22.9 GB`,
  `firmdura-kirkstone-vex-db` `6.98 GB`, `firmdura-kirkstone-sti115-replay`
  `4.2 GB` after `tmp` cleanup, `firmdura-kirkstone-scanner` `3.48 GB`, plus
  bootstrap volumes).
- **Host durable artifact & log store (`local://firmdura-kirkstone/`)**:
  **`19,775,819,776` bytes (`18.42 GiB`)**.
- **Infrastructure cost**: **`$0.00` incremental dedicated cloud VM or signing
  spend** (builds ran on existing local hardware; public-repository GitHub
  Actions `ubuntu-24.04` workflow runs and public Sigstore Fulcio/Rekor keyless
  signing incurred zero separate cloud charges). Workstation hardware
  depreciation, electricity, and general AI/developer tool subscriptions were
  not metered per project and are reported as `null` rather than estimated.

## Demonstrated scope, failures encountered, and open items

### What was demonstrated

- A minimal, separately consumable Yocto Kirkstone `bbappend`
  ([`recipes-connectivity/libwebsockets/`](../recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend))
  repairing `CVE-2026-19773` in `libwebsockets` `4.2.2` (`qemuarm64`, Poky
  `4.0.35`, `PACKAGECONFIG = "libuv client server http2 ssl"`), verified by
  target OOB reproduction on `baseline`, bounds enforcement + post-attack HTTP/2
  service + `ptest` on `patched`, compiled incomplete-fix controls, and
  independent clean-volume source rebuilds producing byte-identical ELF binaries.
- Deterministic `179`-document Yocto SPDX 2.2 consolidation, rootfs-SHA-256
  OpenVEX v0.2.0 scoping (`fixed` on `patched` only), paired positive/negative
  offline Grype `0.122.0` consumer controls, complete corresponding-source and
  case-preserving licence redistribution (`436.65 MB`), and human-gated keyless
  Cosign release signing (`v0.1.0`).

### What was NOT demonstrated

- Compatibility with physical ARM64 boards, vendor BSP layers, other
  `PACKAGECONFIG` combinations, or production-hardened images (`debug-tweaks` is
  enabled solely for unattended QEMU evaluation).
- Stock Anchore Grype CPE detection of `CVE-2026-19773` prior to NIST NVD
  populating CPE configurations, or upstream maintainer merge of
  [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283).

### Technical failures encountered and resolved during the cycle

1. **Raw Yocto SPDX root-document blindness (`0` Grype packages)**: Yocto emits
   `179` split JSON files with `http://spdx.org/rdf/references/cpe23Type` URIs on
   `SPDXRef-Recipe-*` nodes skipped by Syft; solved deterministically in
   [`scripts/vex/normalize_spdx.py`](../scripts/vex/normalize_spdx.py).
2. **Upstream NVD `Awaiting Analysis` gap (`0` stock CPE rows)**: Bridged without
   falsifying stock Grype output or Poky distro identity via offline OSV Git
   provenance ([`scripts/vex/osv_git_provenance.py`](../scripts/vex/osv_git_provenance.py))
   plus an isolated, explicitly labelled test-only CPE SQLite fixture
   ([`scripts/vex/build_aux_grype_db.py`](../scripts/vex/build_aux_grype_db.py)).
3. **Single-maintainer `prevent_self_review` deadlock**: Adjusted
   [`scripts/release/approval.py`](../scripts/release/approval.py) so a
   single-owner repository still enforces explicit human deployment approval on
   `release-signing` (`can_admins_bypass: false`, `main`-only branch policy)
   without deadlocking when dispatcher and reviewer are the same human account.
4. **Yocto `glibc-2.35` `shared-source` archiver omission**: `archiver.bbclass`
   emits `0` tarballs under `deploy/sources/.../glibc-*` because `glibc` builds
   from `work-shared`; [`scripts/bundle/package_bundles.py`](../scripts/bundle/package_bundles.py)
   exports and checksum-verifies the exact `glibc-2.35` Git archive
   (`bb59339d...`) so corresponding source has zero gaps.
5. **GitHub REST API draft-release visibility in `release.yml`**: Initial
   `kind=release` signing run [`44370405253`](https://github.com/firmdura/meta-firmdura-kirkstone/actions/runs/44370405253)
   failed closed in `0.4 s` because `contents: read` tokens cannot list
   `draft: true` releases. Added non-OIDC `main`-only
   [`stage-candidate.yml`](../.github/workflows/stage-candidate.yml) (run
   `44372854449`, immutable `artifact_id=14460645429`) so `release.yml` remained
   strictly read-only in run `44372975734` with zero changes to the approved
   candidate bytes.

## Bottlenecks and capacity observations for follow-up planning

1. **Reusable infrastructure lowers marginal per-CVE effort**: Cold Yocto
   bootstrap + base `sstate-cache` (`5,367 s`), SPDX consolidation, OpenVEX
   tooling, bundle/redistribution packaging, and keyless signing workflows are
   now reusable; warm-base-sstate clean-target rebuilds took **`151`–`156 s`**
   per variant.
2. **Primary remaining per-CVE engineering cost is custom C reproduction and
   root-cause verification**: Writing a deterministic target C harness covering
   upstream edge cases (such as `==` vs `>=` and `?` vs `;` URI-argument splits)
   remains bespoke engineering work for each vulnerability.
3. **Storage & bandwidth constraints**: A `55 GiB` builder disk requires
   `rm_work` and sequential `tmp` cleanup (`~14 GiB` headroom remaining), and
   redistributing a `436.65 MB` full-image corresponding-source archive per
   release consumes ~`6.5` minutes per upload on residential bandwidth unless
   unchanged base-image source archives are deduplicated across point releases.
4. **Human review & NVD feed latency**: Human approval checkpoints (`release-signing`
   and pair freeze) are essential trust gates that bound turnaround to reviewer
   availability, and newly disclosed CVEs frequently lack NVD CPE rows for days
   or weeks after upstream Git fixes land. See
   [the maintenance boundary and decision](maintenance-decision.md) for the
   approved post-`v0.1.0` disposition.
