# Artifact-specific OpenVEX generation and Grype consumer verification

This guide documents the reviewed OpenVEX v0.2.0 statement
([`vex/firmdura-kirkstone-cve-2026-19773.openvex.json`](../vex/firmdura-kirkstone-cve-2026-19773.openvex.json)),
its generator and verifier in
[`scripts/vex/generate_openvex.py`](../scripts/vex/generate_openvex.py),
unit tests in [`tests/vex_test.py`](../tests/vex_test.py), and the paired
consumer verification recorded in
[`evidence/20261118-sti113-openvex/run.json`](../evidence/20261118-sti113-openvex/run.json).

## Distinct image-hash product identities

A generic `libwebsockets` `4.2.2` component identifier cannot distinguish the
vulnerable `baseline` build from the Yocto-backported `patched` build because
both recipes carry `PV = "4.2.2"` (`cpe:2.3:a:*:libwebsockets:4.2.2:*:*:*:*:*:*:*`).
[`scripts/vex/normalize_spdx.py`](../scripts/vex/normalize_spdx.py) binds each
consolidated SPDX 2.2 document's root source element (`SPDXRef-DocumentRoot-File-*`)
to the exact `.rootfs.ext4` SHA-256 digest, producing two disjoint product
PURLs decoded directly by
[Grype `0.122.0`'s OpenVEX processor](https://github.com/anchore/grype/blob/4419483072181b643c3efde0fd15b9113d88887f/grype/vex/openvex/implementation.go#L67):

| Variant | `.rootfs.ext4` SHA-256 | Grype OpenVEX product PURL | OpenVEX disposition |
|---|---|---|---|
| `patched` | `92a3d9f9aaf40de580590bff13774d39b51aab8b3494b1e14bea1963e344598d` | `pkg:generic/firmdura-reference-patched-qemuarm64-20261118120234@1.0-sha256.92a3d9f9aaf40de580590bff13774d39b51aab8b3494b1e14bea1963e344598d` | `fixed` |
| `baseline` | `6f18018f84e0799faeb30a892f827500e209f7831305748eeb64f41813e197a2` | `pkg:generic/firmdura-reference-baseline-qemuarm64-20261118113155@1.0-sha256.6f18018f84e0799faeb30a892f827500e209f7831305748eeb64f41813e197a2` | `affected` |

No subcomponent PURLs, OS/distro overrides, or customer-firmware claims are
made; statements apply solely to these exact reference image digests.

## Dual-track verification matrix (`Grype 0.122.0` + OSV Git provenance)

All Grype scans ran offline (`--network none`, `--read-only`,
`validate-by-hash-on-start=true`, `add-cpes-if-none=false`, zero user ignore
rules) with pinned `docker.io/anchore/grype@sha256:68205d0d11c88aec5999c3139b04ebc242f8b41c40322d2a56b7e880f1e641b4`:

| Track / Database | Input SBOM (`41` packages) | `--vex` document | Active matches | Active `CVE-2026-19773` | Ignored `CVE-2026-19773` | Outcome |
|---|---|---|---:|---:|---:|---|
| Auxiliary CPE test DB (`TEST-ONLY-AUXILIARY-CPE-FIXTURE-NOT-OFFICIAL-ANCHORE-FEED`) | `baseline-41pkg-consolidated.spdx.json` | None | `154` | **`3`** (`libwebsockets18`, `libwebsockets-evlib-uv`, `libwebsockets-testapps`) | `0` | Unfiltered baseline finding established |
| Auxiliary CPE test DB | `patched-41pkg-consolidated.spdx.json` | None | `154` | **`3`** (`libwebsockets18`, `libwebsockets-evlib-uv`, `libwebsockets-testapps`) | `0` | Unfiltered patched CPE finding established prior to VEX |
| Auxiliary CPE test DB (**Positive control**) | `patched-41pkg-consolidated.spdx.json` | `firmdura-kirkstone-cve-2026-19773.openvex.json` | `151` | **`0`** | **`3`** (`namespace: "vex"`, `vex-status: "fixed"`) | Repaired image receives `fixed` disposition; all `151` unrelated matches remain visible |
| Auxiliary CPE test DB (**Mandatory negative control**) | `baseline-41pkg-consolidated.spdx.json` | **Same** `firmdura-kirkstone-cve-2026-19773.openvex.json` | `154` | **`3`** | **`0`** | Patched OpenVEX does **not** suppress the vulnerable baseline's finding |
| Stock Anchore DB `v6.1.10` (`2026-11-18T06:21:08Z`) | `baseline` & `patched` (`41` packages) | None and `--vex` | `151` | `0` (NVD `Awaiting Analysis`) | `0` | Stock feed output preserved truthfully; `--vex` ingests cleanly without altering stock matches |
| Companion OSV Git/source provenance (`osv_git_provenance.py`) | `baseline` vs `patched` canonical `deploy.tar` | None | — | `3` (`baseline`) vs `0` (`patched`) | — | `affected` on `baseline` vs `fixed_by_verified_backport` (`CVE-2026-19773-1.patch`) on `patched` |

## Regeneration and replay commands

```sh
python3 scripts/vex/generate_openvex.py generate \
  --baseline-spdx-manifest "<store>/artifacts/20261118-sti110-patched/sbom/baseline-41pkg-manifest.json" \
  --patched-spdx-manifest "<store>/artifacts/20261118-sti110-patched/sbom/patched-41pkg-manifest.json" \
  --output vex/firmdura-kirkstone-cve-2026-19773.openvex.json

python3 -m unittest discover -s tests -p vex_test.py -v
```

See [the scanner guide](scanner.md) for the consolidation invariants and why the
labelled auxiliary SQLite database is kept strictly isolated in test storage and
never distributed as an official vulnerability feed.
