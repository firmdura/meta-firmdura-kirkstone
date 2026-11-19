# First release build and validation review

This review covers the build, validation, and publication of the signed
[`v0.1.0` reference release](release.md). The
[build measurements](../evidence/20261118-sti117-cycle-review/run.json)
include per-phase build times and builder resources.

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

## Build duration

- **Total BitBake image build time (`6` builds)**: **`5,826.392 s` (`1.618 h`)**
  (`92.1%` spent in the single initial cold build `5,366.709 s`; subsequent
  warm-base-sstate builds took `114.99 s`–`155.53 s`).

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
  signing incurred zero separate cloud charges). The figure excludes workstation
  depreciation, electricity, and software subscriptions.

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
   or weeks after upstream Git fixes land.
