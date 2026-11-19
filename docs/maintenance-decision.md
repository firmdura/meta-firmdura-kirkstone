# Release scope and package audit

The signed [`v0.1.0` release](release.md) covers the `libwebsockets` 4.2.2
repair for CVE-2026-19773 on the pinned `qemuarm64` image. The release includes
QEMU evaluation bundles, corresponding source and licences, an SPDX 2.2 SBOM,
and an image-specific OpenVEX statement. See the [independent replay](replay-review.md)
for rebuild results.

The reference release carries no recurring update schedule or support SLA.
Published tags and release assets are immutable. A material defect in
`v0.1.0` or its redistribution archives requires a versioned correction or a
documented withdrawal that preserves provenance.

## Package audit

The [audit record](../evidence/20261118-sti118-maintenance-decision/run.json)
lists the package versions and findings for the 41-package reference image.

The audit compared stock Grype 0.122.0 user-space matches in
`patched-41pkg-consolidated.spdx.json` with the recipes in the locked layers:
`poky` (`93431249a6...`), `meta-openembedded` (`ce8539c941...`), and
`garmin/meta-lts-collab` (`e127ed67e7...`). Yocto recipes can carry fixes
without changing the package version reported by the scanner.

| Installed package (`PV`) | Stock Grype `0.122.0` CVE match(es) | Recipe or configuration evidence | Audit result |
|---|---|---|---|
| `libuv1` (`1.44.2`) | `CVE-2024-24806` | `CVE-2024-24806-{1,2,3}.patch` already applied in `poky/meta/recipes-connectivity/libuv/libuv_1.44.2.bb` | Already fixed in Poky. The `PV` remains `1.44.2`. |
| `libz1` (`1.2.11`) | `CVE-2022-37434`, `CVE-2018-25032` | `CVE-2022-37434.patch` & `CVE-2018-25032.patch` already applied in `poky/meta/recipes-core/zlib/zlib_1.2.11.bb` | Already fixed in Poky. |
| `busybox` (`1.35.0`) | `CVE-2022-48174`, `CVE-2022-28391`, `CVE-2022-30065` | Patches already applied in `poky/meta/recipes-core/busybox/busybox_1.35.0.bb` | Already fixed in Poky. |
| `libwebsockets18` (`4.2.2`) | `CVE-2025-1866` | Win32-specific / gated on non-default `LWS_WITHOUT_EXTENSIONS=OFF` or `LWS_WITH_HTTP_STREAM_COMPRESSION=ON` (disabled in [`libwebsockets_4.2.2.bb`](scanner.md)) | `not_affected` on the audited image (`code_not_in_execute_path`) |
| `libblkid1` (`2.37.4`) | `CVE-2026-53615` (`High`) | Unpatched across `poky`, `meta-openembedded`, and `garmin/meta-lts-collab` (`parse_dos_extended()` in `libblkid/src/partitions/dos.c`, fixed upstream in `util-linux` `2.41.4`) | Unpatched in the audited image |
| `libcrypto3` / `libssl3` (`3.0.22`) | `CVE-2026-84782` (`High`), `CVE-2026-107496` (`High`) | Unpatched at locked `meta-lts-collab` `e127ed67e7...` (fixed upstream in OpenSSL `3.0.23` / `3.0.24`) | Unpatched in the audited image |
| `busybox` (`1.35.0`) | `CVE-2025-60876` (`Medium`) | Unpatched across `poky` and `meta-lts-collab` (`wget` HTTP request-target CR/LF injection) | Unpatched in the audited image |

The existing Poky fixes can support a `fixed` VEX assessment for this image.
The release’s published OpenVEX statement covers CVE-2026-19773 only.
