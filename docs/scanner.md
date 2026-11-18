# Baseline SBOM graph normalization and scanner interoperability

This document defines the reusable Yocto SPDX 2.2 consolidation contract
implemented in [`scripts/vex/normalize_spdx.py`](../scripts/vex/normalize_spdx.py),
its unit tests in [`tests/scanner_test.py`](../tests/scanner_test.py), and the
bounded 2026-11-18 consumer/feed diagnostic recorded in
[`evidence/20261118-sti119-scanner-preflight/run.json`](../evidence/20261118-sti119-scanner-preflight/run.json).

The SBOM graph and CPE reference-type interoperability gap from
[baseline checks and scanner preflight](testing.md) is resolved: Pinned Grype
`0.122.0` (embedded Syft `1.57.2`) now catalogs all **39 installed target
binary packages** from a single deterministic SPDX 2.2 document bound to the
exact image rootfs SHA-256 and evaluates full-image vulnerability matches
offline without fabricating packages, versions, PURLs, CPEs, or OS/distro
identities.

The release gate for scanner matching remains **blocked** on external upstream
vulnerability feed data: as of `2026-11-18T09:02:21Z`, unfiltered scans with the
newer Grype database snapshot (`v6.1.10`, built `2026-11-18T06:21:08Z`) report
**151 matches (68 unique CVEs)** across the 39-package baseline image, including
Win32-only `CVE-2025-1866` on the three installed `libwebsockets` binary
packages, and **0 matches** for `CVE-2026-19773`. Historical baseline artifacts
and [`evidence/20261117-sti108-baseline/run.json`](../evidence/20261117-sti108-baseline/run.json)
remain untouched. Per [the build contract](build.md), runtime reproduction,
repair, and signing preparation proceed independently, while OpenVEX consumer
acceptance, candidate replay, and public release remain gated.

## SPDX 2.2 consolidation contract (`scripts/vex/normalize_spdx.py`)

Yocto Kirkstone (`create-spdx.bbclass`) emits a multi-document SPDX 2.2 graph:

1. The image root document (`*.spdx.json` under `deploy/images/qemuarm64/`)
   declares only `SPDXRef-Image-<image>` plus `externalDocumentRefs` (`39`
   installed binary-package documents and `39` `runtime-*` dependency
   documents).
2. Binary-package documents (`deploy/spdx/qemuarm64/packages/*.spdx.json`) carry
   installed package metadata and packaged file SHA-1/SHA-256 digests, and link
   to their source recipe via `GENERATED_FROM`, without repeating recipe CPEs.
3. Recipe documents (`deploy/spdx/qemuarm64/recipes/recipe-*.spdx.json`) carry
   build-emitted CPE 2.3 locators using the full URI reference type
   `http://spdx.org/rdf/references/cpe23Type`, which
   [Syft `v1.57.2`](https://github.com/anchore/syft/blob/v1.57.2/syft/format/common/spdxhelpers/to_syft_model.go#L866)
   ignores because it checks only for `"cpe23Type"`, and also reference
   build-only host recipes (`*-native`, `*-cross-*`) via `BUILD_DEPENDENCY_OF`.

`scripts/vex/normalize_spdx.py` consumes either a canonical read-only
`deploy.tar` archive directly via Python `tarfile` (avoiding macOS
case-insensitive extraction) or a Linux SPDX directory (`--spdx-root` and
`--spdx-dir`):

```sh
python3 scripts/vex/normalize_spdx.py \
  --deploy-tar "<store>/artifacts/20261117-sti108-baseline/deploy.tar" \
  --expected-deploy-tar-sha256 8b96ae1c0d280cc50b4d1d699d14e4140c6ed81f6f9b4921cbc315ded476de43 \
  --expected-package-count 39 \
  --output "<store>/artifacts/20261118-sti119-scanner-preflight/sbom/baseline-consolidated-normalized.spdx.json" \
  --manifest-out "<store>/artifacts/20261118-sti119-scanner-preflight/sbom/baseline-normalization-manifest.json"
```

### Fail-closed invariants

`normalize_spdx.py` raises `NormalizationError` (CLI exit code `1`) on any of:

- duplicate JSON keys, malformed JSON, or non-`SPDX-2.2` / non-`CC0-1.0`
  headers in any traversed document;
- missing external SPDX documents, conflicting namespace definitions, or any
  `SHA1`/`SHA256` `checksumValue` mismatch across the full transitive
  `externalDocumentRefs` closure (`179` documents and `2,001` edges on the
  baseline image, plus `.spdx.index.json` SHA-1 cross-verification when
  present);
- any dangling local `SPDXRef-*`, `hasFiles` reference, or cross-document
  `DocumentRef-*:SPDXRef-*` relationship endpoint across all traversed documents
  (`11,583` relationship endpoints verified on baseline);
- any discrepancy between root `CONTAINS` installed binary packages and
  `.rootfs.manifest` (`39` packages), missing `GENERATED_FROM` target recipe,
  missing packaged-file SHA-256 digest, or `RUNTIME_DEPENDENCY_OF` edge pointing
  outside the installed package set.

### Exact normalizations and OpenVEX product identity

No packages, versions, CPE locators, PURLs, OS/distro fields, or vulnerability
mappings are invented:

1. **Target-only package scope**: All `179` graph documents are checksum- and
   reference-verified, while the `73` build-only (`*-native`, `*-cross-*`, and
   uninstalled build-dependency) recipe documents are excluded from the target
   image SBOM so host build tools are never scanned as target firmware
   components.
2. **CPE reference-type spelling and recipe propagation**: Where a traced target
   recipe carries `http://spdx.org/rdf/references/cpe23Type`, only
   `referenceType` is rewritten to `cpe23Type` (`27` rewrites across the `27`
   traced target recipes; `zlib` carries two CPEs and meta-package
   `packagegroup-core-boot` carries none). Because Syft `1.57.2` skips `RefB`
   elements of `GENERATED_FROM` relationships (`SPDXRef-Recipe-*`) when
   collecting packages, each traced recipe's normalized `externalRefs` are
   propagated onto its `GENERATED_FROM` installed binary package(s) (`39`
   propagations) while keeping the `27` `SPDXRef-Recipe-*` nodes and
   `GENERATED_FROM` edges intact for SPDX provenance. Any build-traceable `purl`
   external references are preserved verbatim; none are emitted by Yocto
   Kirkstone `create-spdx.bbclass`.
3. **Artifact-specific root source identity**: The image container
   element is emitted as `SPDXRef-DocumentRoot-File-<image-name>` linked via
   `SPDXRef-DOCUMENT DESCRIBES ...`, with `versionInfo` set to
   `<image-version>-sha256.<rootfs_ext4_sha256>` and the `.rootfs.ext4`
   `SHA256` attached in `checksums`. Syft `1.57.2` decodes this root element as
   `source.FileMetadata` (removing it from the scanned package list so exactly
   `39` packages are cataloged), and
   [Grype `0.122.0`'s OpenVEX processor](https://github.com/anchore/grype/blob/4419483072181b643c3efde0fd15b9113d88887f/grype/vex/openvex/implementation.go#L67)
   derives the deterministic image-hash-bound OpenVEX product PURL:
   `pkg:generic/firmdura-reference-baseline-qemuarm64-20261117213416@1.0-sha256.07e2abd01189da6a977eb0ae0c07136079d3a67f260e2c27aef2bb8d311a5e83`.
   Running `normalize_spdx.py` unchanged on both `baseline` and `patched`
   `deploy.tar` archives yields distinct rootfs-SHA-256-bound product PURLs
   (`grype_openvex_product_purl` in `--manifest-out`). Because Grype `0.122.0`
   matches OpenVEX `subcomponents` only via package PURLs (CPE subcomponent
   matching is unimplemented in `grype/vex/openvex`) and Yocto Kirkstone emits
   no PURLs, OpenVEX statements targeting Grype `0.122.0` must scope `products`
   to the exact image-hash product PURL without inventing subcomponent PURLs.

### Baseline normalization audit summary

| Metric | Measured baseline value |
|---|---|
| Input `deploy.tar` SHA-256 | `8b96ae1c0d280cc50b4d1d699d14e4140c6ed81f6f9b4921cbc315ded476de43` (`1,977,942,016` bytes) |
| Raw root image SPDX SHA-256 | `b3adf92dd8cc1cb27823f41c5982f0f72eb41883b0c0eaf24e7201e96f2a5f72` (`44,674` bytes) |
| Rootfs ext4 SHA-256 | `07e2abd01189da6a977eb0ae0c07136079d3a67f260e2c27aef2bb8d311a5e83` (`25,911,296` bytes) |
| Traversed & verified SPDX documents | `179` (`1` root, `39` package, `39` runtime, `27` target recipe, `73` excluded build-only recipe) |
| Verified `externalDocumentRefs` / relationships | `2,001` edges / `11,583` relationships |
| Consolidated SPDX 2.2 SHA-256 | `f09f3b39d0943c99324fbaecb0cb5097d7d277642c4eca8d6bf8378bbc6ab7f3` (`255,725` bytes) |
| Normalization manifest SHA-256 | `571f7742fb2847421e23d3b642288f2cbc61aa310ade26124f76796e247af3e6` (`182,807` bytes) |
| Installed binary packages / packaged files | `39` packages / `183` files (`/usr/lib/libwebsockets.so.18` SHA-256 `77809db0...cfe3ae05a`) |

## Bounded 2026-11-18 scanner and upstream feed check

### Pinned consumer and 2026-11-18 database snapshot

- Latest upstream Grype release checked on `2026-11-18T09:02:17Z`: still
  **`v0.122.0`** (published `2026-11-16T20:41:59Z`, commit
  `4419483072181b643c3efde0fd15b9113d88887f`, embedded Syft **`v1.57.2`**,
  ARM64 image
  `docker.io/anchore/grype@sha256:68205d0d11c88aec5999c3139b04ebc242f8b41c40322d2a56b7e880f1e641b4`).
- Newer Grype v6 database snapshot imported into isolated run storage
  (leaving the earlier `2026-11-17T06:20:58Z` snapshot untouched):
  - Schema **`v6.1.10`**, built **`2026-11-18T06:21:08Z`**.
  - Archive `vulnerability-db_v6.1.10_2026-11-18T00:21:05Z_1794982868.tar.zst`
    (`203,412,394` bytes), SHA-256
    `5029e15a80ebb0ac53cad3413d2768fa241f6e2b71336d8ef73ec5a87e5a4cc0`.
  - Unpacked SQLite `vulnerability.db` (`3,486,990,336` bytes), SHA-256
    `efb6c344f69aebb675b33d7bfd61592226134643fa9db4516d73e77b30911506`.
- All scans executed offline (`--network none`, `--read-only`, database and SBOM
  subpaths mounted `readonly`, `auto-update=false`, hash and age validation
  enabled, `vex-documents=[]`, `distro=""`, `add-cpes-if-none=false`, zero user
  ignore rules, four built-in kernel-header ignore rules).

### Full-image scan comparison

| Offline Grype `0.122.0` input | Cataloged packages | Unfiltered matches | Unique CVEs | `libwebsockets*` matches | `CVE-2026-19773` |
|---|---:|---:|---:|---|---|
| Unmodified raw root image SPDX (`baseline-root-raw.spdx.json`) | `1` | `0` | `0` | None | **Absent (`0`)** |
| Consolidated normalized 39-package SPDX (`baseline-consolidated-normalized.spdx.json`) | `39` | `151` | `68` | `CVE-2025-1866` on `libwebsockets18`, `libwebsockets-evlib-uv`, `libwebsockets-testapps` | **Absent (`0`)** |
| Same consolidated SPDX with `GRYPE_INCLUDE_MATCHER_SUPPRESSIONS=true` | `39` | `151` (`0` ignored) | `68` | `CVE-2025-1866` (`3` package matches) | **Absent (`0`)** |

Across the 39 installed binary packages, the `151` unfiltered CPE matches (`14`
Critical, `56` High, `58` Medium, `23` Low) span `20` binary packages: `libc6`
(`40`), `ldconfig` (`40`), `libcrypto3` (`7`), `libssl3` (`7`), `openssl-conf`
(`7`), `openssl-ossl-module-legacy` (`7`), `busybox` (`6`), `busybox-hwclock`
(`6`), `busybox-syslog` (`6`), `busybox-udhcpc` (`6`), `libblkid1` (`6`),
`liblzma5` (`2`), `libtinfo5` (`2`), `libz1` (`2`), `ncurses-terminfo-base`
(`2`), `libgcc1` (`1`), `libuv1` (`1`), `libwebsockets18` (`1`),
`libwebsockets-evlib-uv` (`1`), and `libwebsockets-testapps` (`1`). All raw
scanner JSON outputs are retained under
`local://firmdura-kirkstone/artifacts/20261118-sti119-scanner-preflight/scans/`.

### Upstream advisory and database status as of 2026-11-18

Single bounded query snapshot retained at
`local://firmdura-kirkstone/artifacts/20261118-sti119-scanner-preflight/feeds/20261118-feed-check.json`
(SHA-256 `340046eb3f2517f0c5cb198aaa666cceaede6b33f83dd51d8f50b02e278ed7e4`):

- **NVD (`CVE-2026-19773`)**:
  [NVD API v2.0](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-19773)
  reports `vulnStatus: "Awaiting Analysis"` (`lastModified:
  "2026-09-18T19:10:46.443"`), `configurations: null`, and only the CNA
  ([ZDI-26-590](https://www.zerodayinitiative.com/advisories/ZDI-26-590/))
  `affected` commit entry `b4b5aed3903eaff09cd76a410f69bbe5dff66f8e`
  (`defaultStatus: "unknown"`) plus the
  [upstream repair commit](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b).
- **Grype SQLite DB (`2026-11-18T06:21:08Z`)**: `vulnerability_handles` lists
  `CVE-2026-19773` under `nvd` (`status = "analyzing"`), `debian` (`active`),
  `echo` (`active`), and `ubuntu` (`active`). `affected_cpe_handles` has **`0`
  rows** for `CVE-2026-19773` (across the entire DB, the only
  `affected_cpe_handles` entry for product `libwebsockets` is `CVE-2025-1866`).
  `affected_package_handles` has `17` rows, all restricted to `ecosystem = "deb"`
  (`debian`, `echo`, `ubuntu`). Neither `add-cpes-if-none` nor an alternate
  CPE vendor can match `CVE-2026-19773` while `affected_cpe_handles` is empty,
  and overriding Poky's distro identity to Debian/Ubuntu would falsify target
  provenance.
- **OSV (`CVE-2026-19773`)**:
  [OSV API](https://api.osv.dev/v1/vulns/CVE-2026-19773) serves an
  auto-converted CVE v5 record (`modified: "2026-10-28T10:50:35.083958267Z"`)
  with **no package ecosystem or PURL**—only a `GIT` commit range
  (`b4b5aed3903eaff09cd76a410f69bbe5dff66f8e` to
  `824151862f37bc72f46d9a3e01d5b9408d313a0b`) and Vanir C function/line
  signatures on `lib/roles/h2/hpack.c` (`lws_frag_append`), which Grype does not
  ingest or evaluate on SPDX package SBOMs.
- **GitHub Advisory Database (`GHSA-r4m8-276f-3r2f`)**:
  [GHSA-r4m8-276f-3r2f](https://github.com/advisories/GHSA-r4m8-276f-3r2f) is
  `type: "unreviewed"` with `vulnerabilities: []` (zero ecosystem/package
  ranges).

## External feed requirements for scanner and OpenVEX acceptance

Continuous feed polling was not performed, and the scanner release gate remains
open. Unblocking unfiltered target detection and downstream OpenVEX matching
requires **one** of:

1. **External feed enrichment (no contract change)**: NVD completes CPE
   applicability analysis for `CVE-2026-19773` (adding a `libwebsockets` CPE
   range covering `4.2.2` prior to `824151862f37bc72f46d9a3e01d5b9408d313a0b`)
   and Anchore publishes a Grype v6 database snapshot containing the resulting
   `affected_cpe_handles` row. Re-running Grype offline against
   `baseline-consolidated-normalized.spdx.json` will then match `libwebsockets18`
   without modifying `scripts/vex/normalize_spdx.py`.
2. **Explicitly reviewed consumer or scope change**: If NVD remains
   `Awaiting Analysis` after runtime reproduction and repair finish:
   - hold release publication until NVD/Grype DB enrichment lands;
   - evaluate an explicitly reviewed commit- or signature-aware companion
     consumer (for example OSV git commit/Vanir matching or Yocto `cve-check`)
     or an explicitly labelled auxiliary vulnerability feed for OpenVEX
     consumer-mechanics verification; or
   - select a different Linux-applicable Kirkstone CVE candidate with active
     non-distro CPE coverage in Grype DB v6 (`CVE-2025-1866` is Win32-only and
     remains ineligible).
