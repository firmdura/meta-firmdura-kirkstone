# Firmdura Kirkstone reference sample

A public engineering sample showing the source maintenance layer, integration process, and repair evidence that an embedded Linux engineering team can evaluate.

**Status: the clean baseline image build and QEMU boot/library checks succeeded. Scanner preflight is blocked: the pinned Grype/database combination does not report CVE-2026-19773. No CVE reproduction, validated repair, or sample release is available yet.**

See [the reference build and handoff contract](docs/build.md) for locked inputs,
isolated builder setup, baseline/patched configuration boundaries, commands,
evidence storage, and file ownership. The repair layer is still empty: a
configuration named `patched` is not evidence that a repair has been applied.
The [bootstrap run record](evidence/20261117-sti107-bootstrap/run.json) indexes
the actual commands, configuration comparisons, retained logs and hashes.
The [baseline checkpoint](evidence/20261117-sti108-baseline/run.json) records
the real build, artifact hashes, target observations, and unsuccessful scanner
preflight. See [testing and scanner limitations](docs/testing.md) before
interpreting an empty scan as a security result.

## Planned first release

- One upstream-backed libwebsockets security repair, initially CVE-2026-19773, subject to confirming applicability on the selected build.
- One pinned Yocto Kirkstone reference configuration, starting with Poky 4.0.35, meta-openembedded, and Garmin's meta-lts-collab.
- One virtual ARM64 machine, `qemuarm64`, with baseline and patched variants of the same reference image.
- Actual Yocto package/image builds, a meaningful failing-before/passing-after security test, and normal-functionality regression checks.
- Human-reviewed evidence tied to the exact tested artifacts.

The existing upstream repair is the starting point, not a claim that this repository has discovered a new vulnerability or already completed a backport.

## What engineers will receive

The first tagged release is intended to include:

- The source layer, patches, provenance, licences, and locked build configuration.
- Runnable security/regression tests, raw logs, and machine-readable results.
- Minimal baseline and patched QEMU evaluation bundles, with boot/test instructions.
- Required corresponding source, build material, licences, and notices for distributed binaries.
- SBOMs and artifact-specific OpenVEX statements.
- A release manifest binding the asset hashes and a Cosign Sigstore verification bundle.
- Scope, limitations, unresolved findings, and instructions for verifying and reproducing the release.

There will be two evaluation paths:

1. **Quick evaluation:** verify the signed manifest and downloaded assets, boot the reference images, and run the tests.
2. **Full reproduction:** build and test from the documented, pinned source inputs.

The baseline is for isolated testing only. Neither image is production firmware, and both may contain other unresolved vulnerabilities. There is no general package feed or device-update service.

## Signing and VEX

The planned signing mechanism is **Cosign keyless signing through GitHub Actions**, without a long-lived signing private key. Verification instructions will require the expected repository/workflow/release identity and GitHub Actions issuer, not merely any valid signature.

**OpenVEX will be tested with Grype.** Its integration must demonstrate that the patched release's statement applies to the tested repaired artifact and does not suppress the finding on the vulnerable baseline. Selecting Grype does not imply that this artifact-matching integration is already validated.

## Implementation choices

| Area | Language or format |
|---|---|
| Component repair and low-level security tests | C |
| Yocto layer integration | BitBake recipes/appends and configuration |
| Build and release configuration | YAML for kas and GitHub Actions |
| Verification glue | Existing Python/Yocto test facilities and short shell commands |
| Reusable Firmdura CLI/library tooling, where needed | Go |
| Evidence and documentation | JSON and Markdown |

This sample does not require building a general orchestration platform.

## Scope and next milestone

The baseline now builds and boots, including the intended shared library and
HTTP/2 configuration. On 2026-11-18, the owner chose to hold CVE-2026-19773
pending suitable scanner data/integration. No replacement case or acceptance
waiver is authorized. STI-108 is not Done and the repair path remains paused;
STI-111 signing work is independently ready. Security comparison, repair
integration, release assembly, and internal clean-environment replay remain
unverified.

Customer participation, external replay, physical-board qualification, and community PR acceptance are not prerequisites for publishing this sample.

Results will apply only to the stated reference configuration. They will not establish compatibility with every Kirkstone BSP, validate customer firmware, or certify compliance. Customer product builds, hardware tests, approval, signing, and deployment remain under customer control.

The first commitment is one complete sample. Additional cases and a maintenance cadence will be considered after measuring the first cycle.

## Licensing

[MIT](LICENSE) applies to original Firmdura files, with owner approval.
Third-party layers, patches, sources, and distributed binaries retain their
own licences and notices; see [the licence boundary](docs/build.md#licence-boundary).

## References

- [libwebsockets advisory: ZDI-26-590](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)
- [Upstream libwebsockets repair](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)
- [Garmin meta-lts-collab](https://github.com/garmin/meta-lts-collab/tree/kirkstone)
- [Cosign file signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [Grype OpenVEX support](https://oss.anchore.com/docs/guides/vulnerability/filter-results/#use-vex-documents)
