# First release build and validation review

This review covers the build, validation, and publication of the signed
[`v0.1.0` reference release](release.md). The
[build measurements](../evidence/20261118-sti117-cycle-review/run.json)
include per-phase build times and builder resources.

## Release timeline

| Event | Time (UTC) | Record |
|---|---|---|
| Upstream `CVE-2026-19773` NVD entry last modified (`Awaiting Analysis`) | `2026-09-18T19:10:46Z` | [ZDI-26-590](https://www.zerodayinitiative.com/advisories/ZDI-26-590/), [upstream fix `824151862f`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b) |
| Upstream OSV `CVE-2026-19773` record modified (`GIT` range only) | `2026-10-28T10:50:35Z` | [`docs/scanner.md`](scanner.md) |
| Started builder setup and parsed the locked layers | `2026-11-17T20:59:10Z` | [Run record](../evidence/20261117-sti107-bootstrap/run.json) |
| Completed the cold baseline build and QEMU boot check | `2026-11-18T00:24:25Z` | [Run record](../evidence/20261117-sti108-baseline/run.json) |
| Confirmed CVE-2026-19773 on the baseline `qemuarm64` image | `2026-11-18T11:50:49Z` | [Run record](../evidence/20261118-sti109-reproduction/run.json) |
| Completed the baseline and patched regression tests | `2026-11-18T12:49:29Z` | [Run record](../evidence/20261118-sti110-paired-validation/run.json) |
| Packaged evaluation bundles, corresponding source and licences | `2026-11-18T13:52:44Z` | [Run record](../evidence/20261118-sti112-bundles/run.json) |
| Verified GitHub Actions OIDC signing with a test fixture | `2026-11-18T14:04:03Z` | [Run record](../evidence/20261118-sti111-oidc-fixture/run.json) |
| Upstream contribution [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283) submitted | `2026-11-18T14:13:01Z` | [Run record](../evidence/20261118-sti114-contribution/run.json) |
| Checked scanner and OpenVEX positive and negative controls | `2026-11-18T15:13:06Z` | [Run record](../evidence/20261118-sti113-openvex/run.json) |
| Rebuilt the source on a fresh volume and replayed the candidate tests | `2026-11-18T16:30:59Z` | [Run record](../evidence/20261118-sti115-replay/run.json) |
| Public download verification completed for [`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0) | `2026-11-18T18:52:09Z` | [Run record](../evidence/20261118-sti116-release/run.json) |

## Build time and resources

Six BitBake image builds took 5,826.392 seconds in total (1.618 hours). The
cold build took 5,366.709 seconds, or 92.1% of that time. The five later builds
had different inputs and amounts of reusable state:

| Build | Seconds |
|---|---:|
| Incremental baseline image | 30.06 |
| Paired validation, baseline | 7.99 |
| Paired validation, patched | 114.99 |
| Clean target rebuild with cached dependencies, baseline | 155.53 |
| Clean target rebuild with cached dependencies, patched | 151.12 |

The builder ran Ubuntu 24.04 LTS in a local ARM64 Colima VM on Apple Silicon.
It had 4 vCPUs, 8 GiB of RAM, a 55 GiB data disk, and a 10 GiB root disk. The
host had 95 GiB free.

The kas 4.8 and Grype 0.122.0 images occupied 1.582 GB together. Seven Docker
volumes used 39.84 GB, including 22.9 GB for the baseline build, 6.98 GB for
the VEX database, 4.2 GB for the replay volume after cleanup, and 3.48 GB for
the scanner. The local artifact and log store held 19,775,819,776 bytes (18.42 GiB).

Incremental cloud VM and signing charges were $0.00. Builds used existing
hardware, GitHub Actions used public `ubuntu-24.04` runners, and signing used
public Sigstore Fulcio and Rekor. The figure excludes workstation depreciation,
electricity, and software subscriptions.

## Validation scope

The [layer recipe](../recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend)
repairs CVE-2026-19773 in `libwebsockets` 4.2.2 for the pinned Poky 4.0.35
`qemuarm64` image with `PACKAGECONFIG = "libuv client server http2 ssl"`. The
baseline exhibited the defect. On the patched image, the bounds checks held,
HTTP/2 continued serving, and `ptest` passed. Tests also distinguished incomplete
repairs. Independent builds on a clean volume produced byte-identical ELF files.

The release consolidates 179 Yocto SPDX 2.2 documents. Its OpenVEX v0.2.0
statement identifies the patched root filesystem by SHA-256. Offline Grype
0.122.0 checks covered both images with and without the statement. The release
includes corresponding source and licences (436.65 MB), preserves licence
filename case, and was signed with Cosign after deployment approval.

Testing covered the reference image with `debug-tweaks` enabled for unattended
QEMU use. Physical boards, vendor BSP layers, other `PACKAGECONFIG` values, and
production-hardened images were outside this run. At release time, the stock
Grype database had no CPE match for this CVE. The timeline records the upstream
submission date (`2026-11-18`); a `meta-lts-collab` maintainer subsequently
approved CI and merged [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283)
into `kirkstone` on `2026-11-20`
([`c1af581260`](https://github.com/garmin/meta-lts-collab/commit/c1af58126047932d50ffac47e925d1399c162aa3)).

## Problems encountered

1. **Grype reported zero packages from the SPDX root document.** The image SBOM
   was split over 179 files. Syft skipped the CPE references on `SPDXRef-Recipe-*`
   nodes. The [normalizer](../scripts/vex/normalize_spdx.py) consolidates those
   documents and maps the references for scanning.
2. **The stock database lacked a CPE record for this CVE.** NVD listed it as
   `Awaiting Analysis`. The stock Grype result was kept. The [OSV Git check](../scripts/vex/osv_git_provenance.py)
   compared upstream revisions, and a [separate test database](../scripts/vex/build_aux_grype_db.py)
   supplied the CPE match for the VEX controls. The reference image kept its original Poky
   distribution identity.
3. **The repository owner could not approve a signing run they started.** The
   `prevent_self_review` setting blocked approval in the single-maintainer repo.
   The [`release-signing` check](../scripts/release/approval.py) allows the
   dispatcher to approve explicitly. Deployments still require approval, use
   `main` only, and prohibit admin bypass.
4. **The Yocto archiver omitted glibc.** glibc 2.35 builds from `work-shared`,
   so `archiver.bbclass` emitted no tarballs under `deploy/sources/.../glibc-*`.
   The [packager](../scripts/bundle/package_bundles.py) exported and checked the
   corresponding source archive from Git revision `bb59339d...`.
5. **The signing job could not see the draft release.** The [first signing run](https://github.com/firmdura/meta-firmdura-kirkstone/actions/runs/44370405253)
   stopped after 0.4 seconds because its `contents: read` token could not list
   draft releases. The [staging workflow](../.github/workflows/stage-candidate.yml)
   on `main` (run `44372854449`) supplied artifact `14460645429` without OIDC.
   The read-only signing workflow used the same approved bytes in run `44372975734`.

## Limits on repeat builds

The cached build state, SBOM tooling, packaging, and signing workflow can be
reused. The clean target rebuilds took 151 to 156 seconds per variant. The
regression tests were specific to this defect and required separate engineering
work. Release timing also depended on review of the image pair and approval for
signing. The stock scanner still lacked CPE data when this release shipped.

On the 55 GiB builder disk, using `rm_work` and clearing `tmp` between builds
left about 14 GiB free. Uploading the 436.65 MB corresponding-source archive
took about 6.5 minutes on the connection used for this release. Reusing unchanged
base-image source archives across releases would reduce future uploads.
