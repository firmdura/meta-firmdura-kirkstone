# Public maintenance boundary and post-`v0.1.0` decision

This document records the post-cycle maintenance decision following publication
of signed reference release
[`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0)
([release index](release.md)) and the reconciled operating measurements in
[the first-cycle review](first-cycle-review.md). Structured applicability check
outputs and decision metadata are recorded in
[`evidence/20261118-sti118-maintenance-decision/run.json`](../evidence/20261118-sti118-maintenance-decision/run.json).

## Approved status: verified single-case `v0.1.0` sample (`defer` additional cases)

On `2026-11-18`, following review of the first-cycle effort, reusable tooling,
open external items, and candidate CVE applicability across the `41`-package
`qemuarm64` image, the project owner approved **preserving this repository as a
completed, verified one-off `v0.1.0` public sample (`no-go / defer` on
additional CVE backports at this time)**:

- **Preserved `v0.1.0` status**: Signed release [`v0.1.0`](release.md) remains
  publicly available and self-contained—including the scoped `libwebsockets`
  `4.2.2` `CVE-2026-19773` repair layer, offline QEMU evaluation bundles,
  complete corresponding source and licences, consolidated SPDX 2.2 SBOMs,
  image-hash-scoped OpenVEX statement, and independent clean-volume replay
  evidence ([replay review](replay-review.md))—with no external reviewer or
  customer participation required as a prerequisite.
- **No implied ongoing cadence, SLA, or EOL support**: No recurring update
  schedule, vulnerability-monitoring SLA, universal CVE coverage, or open-ended
  Yocto Kirkstone end-of-life support is promised or implied.
- **Defect and withdrawal handling**: Existing published tags and release assets
  (`v0.1.0`) are immutable and will never be overwritten in place. If a material
  defect is discovered in `v0.1.0` or its redistribution archives, it will be
  handled solely through an explicit versioned correction (`v0.1.1`) or a
  documented withdrawal notice preserving verifiable provenance.

## Traceability to first-cycle measurements and candidate audit

### Operating baseline ([`docs/first-cycle-review.md`](first-cycle-review.md))

- **Measured effort**: `20,051.46 s` (`5.570 h`) of non-overlapping strictly
  metered active assistant-session time (`23,098.98 s` / `6.416 h` cumulative
  across parallel streams; initial `2026-11-17` bootstrap/cold-build active
  intervals and direct human UI review minutes remain `null` / uninstrumented),
  `5,826.39 s` (`1.618 h`) across `6` BitBake builds, and `$0.00` incremental
  cloud infrastructure billing (`39.84 GB` across `7` local Colima Docker
  volumes; `18.42 GiB` host durable store).
- **Reusable vs bespoke effort**: While SPDX consolidation, OpenVEX generation,
  bundle/redistribution packaging, keyless Cosign workflows, and warm
  base-system `sstate-cache` (`151`–`156 s` clean-target rebuilds vs `5,367 s`
  cold build) are reusable, each new vulnerability still requires bespoke C
  target reproduction/regression harnesses, `477 MB` source-archive transfer
  handling, and synchronous human owner review/signing gates.
- **Pending external signals from Cycle 1**:
  1. Upstream community review/CI disposition on
     [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283)
     ([contribution record](contribution.md));
  2. NIST NVD CPE configuration enrichment for `CVE-2026-19773` (currently
     `Awaiting Analysis`, leaving `0` CPE rows in stock Anchore Grype DB
     `v6.1.10`).

### Empirical applicability & community-repair audit on the `41`-package image

To avoid inflating potential backport counts with upstream or community patches
already present in the pinned layers, stock Grype `0.122.0` user-space matches
on `patched-41pkg-consolidated.spdx.json` were cross-checked directly against
the locked `poky` (`93431249a6...`), `meta-openembedded` (`ce8539c941...`), and
`garmin/meta-lts-collab` (`e127ed67e7...`) recipe trees:

| Installed package (`PV`) | Stock Grype `0.122.0` CVE match(es) | Verified layer / source status | Honest classification |
|---|---|---|---|
| `libuv1` (`1.44.2`) | `CVE-2024-24806` | `CVE-2024-24806-{1,2,3}.patch` **already applied** in `poky/meta/recipes-connectivity/libuv/libuv_1.44.2.bb` | **Existing Poky community backport** (masked by `PV = "1.44.2"`; VEX `fixed` reuse, never a new backport) |
| `libz1` (`1.2.11`) | `CVE-2022-37434`, `CVE-2018-25032` | `CVE-2022-37434.patch` & `CVE-2018-25032.patch` **already applied** in `poky/meta/recipes-core/zlib/zlib_1.2.11.bb` | **Existing Poky community backports** (VEX `fixed` reuse, never new backports) |
| `busybox` (`1.35.0`) | `CVE-2022-48174`, `CVE-2022-28391`, `CVE-2022-30065` | Patches **already applied** in `poky/meta/recipes-core/busybox/busybox_1.35.0.bb` | **Existing Poky community backports** (VEX `fixed` reuse, never new backports) |
| `libwebsockets18` (`4.2.2`) | `CVE-2025-1866` | Win32-specific / gated on non-default `LWS_WITHOUT_EXTENSIONS=OFF` or `LWS_WITH_HTTP_STREAM_COMPRESSION=ON` (disabled in [`libwebsockets_4.2.2.bb`](scanner.md)) | **Configuration/platform `not_affected`** (`code_not_in_execute_path`), not a Linux target repair |
| `libblkid1` (`2.37.4`) | `CVE-2026-53615` (`High`) | Unpatched across `poky`, `meta-openembedded`, and `garmin/meta-lts-collab` (`parse_dos_extended()` in `libblkid/src/partitions/dos.c`, fixed upstream in `util-linux` `2.41.4`) | Candidate unpatched user-space case (deferred) |
| `libcrypto3` / `libssl3` (`3.0.22`) | `CVE-2026-84782` (`High`), `CVE-2026-107496` (`High`) | Unpatched at locked `meta-lts-collab` `e127ed67e7...` (fixed upstream in OpenSSL `3.0.23` / `3.0.24`; if `meta-lts-collab` bumps `3.0.x` first, classify as community update reuse) | Candidate unpatched user-space case (deferred) |
| `busybox` (`1.35.0`) | `CVE-2025-60876` (`Medium`) | Unpatched across `poky` and `meta-lts-collab` (`wget` HTTP request-target CR/LF injection) | Candidate unpatched user-space case (deferred) |

## Conditions for any future reopening

No follow-up implementation obligations are active. Any future decision to open
a bounded multi-case experiment requires explicit new owner authorization
specifying:

1. Named human reviewer capacity and a finite timebox (for example, a 3-month
   window with an explicit end/review date and permitted quiet periods when no
   in-scope upstream-fixed vulnerability qualifies);
2. Exact package/configuration scope on the pinned `qemuarm64` reference image,
   separating genuine new backports from reused `poky` / `meta-lts-collab`
   community updates and `not_affected` VEX dispositions; and
3. Preservation of all paired runtime verification, SPDX/OpenVEX positive and
   negative controls, complete corresponding-source redistribution, and
   human-approved keyless Cosign signing gates established in `v0.1.0`.
