# Pinned reference build and handoff contract

The STI-107 bootstrap and STI-108 baseline build/boot are verified, but the
scanner preflight is blocked. This is not a CVE reproduction.
The repair layer is currently empty. The `patched` configuration
reserves the comparison interface; its name does **not** mean it contains a
repair. Only STI-110 can establish that distinction with actual target evidence.

The [bootstrap run record](../evidence/20261117-sti107-bootstrap/run.json)
records a public-source clean checkout, 2,427 parsed recipes, and an image
dependency dry-run of 4,921 tasks. Those dry-run tasks did **not** build an
image. Expanded baseline configuration and relevant effective
baseline/patched feature settings matched. The ownership correction to the
container helper was separately verified with another new empty volume;
it did not change the locked configuration, image recipe or layer files.

The [baseline checkpoint](../evidence/20261117-sti108-baseline/run.json) records
the actual clean build at `209222b2f7fbd6a30257b0e064d3f4df18e23692`:
4,921 executed tasks, no reused downloads or sstate, 5,366.709314 seconds,
and four retained warnings. Its QEMU checks identify the installed library
and HTTP/2 support, not a vulnerability or repair. See
[the test procedure and scanner blocker](testing.md).

## Locked inputs

Resolved from the public repositories on 2026-11-17:

| Input | Immutable identity | Selection |
|---|---|---|
| Poky | `93431249a6260da7bd29ee3ca32145d89e5b8259` | Peeled `yocto-4.0.35` tag |
| meta-openembedded | `ce8539c941f6fcbecaca4d16640ac105c0595589` | Current `kirkstone` |
| Garmin meta-lts-collab | `e127ed67e74ca6b7e0fdc6cbda572302886c00a0` | Current `kirkstone` |
| kas | `4.8`, source `aad407493fe97d0e8bf0f9c2ee292ee9632b8267` | Released tag, not a development build |
| ARM64 kas container | `sha256:718b8f0dbf8174645ddb18c7979e7a635a4ed7bd55e750d75c1c8091454b8ce7` | Released `ghcr.io/siemens/kas/kas:4.8` platform manifest |

The URLs and commit locks are in [the common configuration](../kas/common.yml);
the executable container identity is in [builder-image.txt](../kas/builder-image.txt).
The local sample repository must also be checked out at the exact source SHA
recorded for the run. A tag or branch name alone is not a reproducible handoff.

The selected recipe is `meta-oe/recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bb`,
whose source commit is `8d605f0649ed1ab6d27a443c7688598ea21fdb75`. Both variants
explicitly enable `libuv client server http2 ssl`, use dynamic test applications,
and install `libwebsockets`, `libwebsockets-testapps`, and `ptest-runner`.
The shared image recipe lives only in the test layer.
The same meta-openembedded pin supplies `meta-networking` and `meta-python`:
the enabled ptest dependency graph needs `stunnel`, and the networking layer
declares the Python layer as a dependency. Do not mask the missing provider by
disabling tests in only one variant.

The [advisory](https://www.zerodayinitiative.com/advisories/ZDI-26-590/) identifies
the HTTP/2 HPACK path-header boundary. The
[upstream change](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)
adds a bound check in `lws_frag_append`. The selected current community tree has
no libwebsockets recipe or append, and the public community PR/CVE searches
returned no matches at bootstrap. These observations are **not** proof that
the built target is affected. STI-108/109 must check the actual package,
configuration, scanner result, and runtime failure. Never remove an existing
fix or select an older community revision to manufacture a vulnerable baseline.

## Builder and authorization

Use an isolated, maintained **Linux ARM64** builder. macOS is a control host,
not the Yocto host filesystem. This container is specifically pinned for
ARM64; other builder architectures are not validated by this bootstrap.

The owner approved dedicated local Linux environments and durable local
artifact storage for this sample on 2026-11-17. That standing authorization is
recorded on STI-106 and STI-107; do not ask for it again within that scope.
It does not authorize spending, changes to other workloads, or release
publication. Jabar Asadi is the human engineering/release reviewer. Original
files are MIT with owner approval; third-party terms remain unchanged.

The initial dedicated Colima profile is `firmdura-kirkstone`: native ARM64,
4 virtual CPUs, 8 GiB RAM, a 55 GiB data disk and a 10 GiB root disk. Its VM
uses Ubuntu 24.04 LTS; the pinned kas container supplies the build userspace.
Existing Colima profiles, Docker's default context, and shared workloads are
not part of this sample. Use `DOCKER_CONTEXT=colima-firmdura-kirkstone` on each
local Docker/helper command rather than changing the default context.

This is a constrained minimal-image experiment, not a claim that 55 GiB
suffices for arbitrary Yocto builds. The
[Yocto requirements](https://docs.yoctoproject.org/4.0.35/ref-manual/system-requirements.html)
recommend at least 90 GB for a larger `core-image-sato` build. The common
configuration limits concurrent tasks, uses `rm_work` (retaining libwebsockets
work for inspection), and stops tasks at 5 GB of free builder storage.
Check the physical host's free space before and throughout builds and exports;
pause this workload if it falls below 25 GiB. Never delete or stop another
workload to make room.

Do not build on the macOS bind mount. Repositories, downloads, sstate and build
outputs belong in a dedicated Docker volume on the Linux data filesystem.
Only the sample checkout is mounted read-only. Do not mount SSH agents,
credential stores, the host home directory, or the Docker socket into the
builder. No container ports are published.
The helper trusts only the explicit read-only `/repo` Git directory inside
the container: a VM bind mount's root can otherwise appear root-owned even
when its files retain the calling user's identity. Host Git settings are not
changed, and no wildcard `safe.directory` exception is used.

## Clean setup and commands

Prerequisites: the approved Linux builder, Docker, the public sample checkout,
and sufficient storage. On macOS, supply the dedicated `DOCKER_CONTEXT`
environment variable to each command below. On an approved native Linux
builder, use its Docker context. Run as a non-root user.

From the sample checkout, initialize a **new, dedicated** work volume:

```sh
docker volume create --label org.firmdura.sample=kirkstone firmdura-kirkstone-work
sh kas/run baseline dump
sh kas/run baseline checkout
sh kas/run baseline shell -c 'bitbake -p'
sh kas/run baseline shell -c 'bitbake-layers show-recipes libwebsockets'
sh kas/run baseline shell -c 'bitbake-layers show-appends'
sh kas/run baseline shell -c 'bitbake -e libwebsockets'
sh kas/run baseline shell -c 'bitbake -e firmdura-reference-image'
```

The helper initializes the work volume's top-level ownership inside the
consuming container, then drops to the calling user's non-root identity.
Do not depend on an earlier disposable container to prepare an empty volume's
ownership. It does not recursively change existing build files.

Capture stdout **and** stderr and preserve each exit status. Do not let a
successful `tee`, grep, or summary replace a failed command's result.
Inspect effective `FILE`, `PV`, `SRCREV`, `SRC_URI`, `PACKAGECONFIG`,
`EXTRA_OECMAKE`, `IMAGE_INSTALL`, `MACHINE`, `TARGET_SYS`, and layer/configuration
identities. A kas dump is not a substitute for BitBake parsing.

For the second clean resolution check, use a second clean checkout at the
same source SHA and a new volume, for example `firmdura-kirkstone-replay`.
Create that volume as above and set
`FIRMDURA_WORK_VOLUME=firmdura-kirkstone-replay` on the helper commands.
Do not copy the first checkout's repositories or generated configuration into
that volume. Compare all external repository commits and the expanded kas
configuration, and record any declared cache/download reuse.

After STI-107 is verified, reviewed and merged, STI-108 runs:

```sh
sh kas/run baseline build
```

The build directory is `/work/build-baseline`; the other variant uses
`/work/build-patched`. Downloads and sstate are shared inside this volume, but
the initial baseline build must use a clean build directory. Record any
reuse explicitly. The two configurations differ only in the variant label,
image basename, and inclusion of the repair layer. Relevant features and
the test revision must remain equal.

The build enables Yocto's SPDX inventory, original-source/patch/recipe
archiving for target recipes, and licence manifests/notices. This starts
source collection early; it is **not** the complete binary redistribution
review, which remains a mandatory STI-112 gate.

## Output, boot and artifact storage

Preserve the actual build outputs, not guessed filenames:

| Container location | Purpose |
|---|---|
| `/work/build-baseline/tmp/deploy/images/qemuarm64/` | Kernel, rootfs, manifest and QEMU configuration |
| `/work/build-baseline/tmp/deploy/ipk/` | Built target packages |
| `/work/build-baseline/tmp/deploy/spdx/` | Actual build SBOMs and referenced documents |
| `/work/build-baseline/tmp/deploy/sources/` | Original sources, patch series and recipes |
| `/work/build-baseline/tmp/deploy/licenses/` | Recipe/image licence information |
| `/work/build-baseline/tmp/work/` | Retained task logs and libwebsockets build/configuration |

Export required logs before deleting a container or cleaning work. `rm_work`
does not replace a run-log retention policy. Transfer outputs using Docker's
copy/archive interfaces to the approved persistent host store; never depend
on an ephemeral container layer. Preserve symlink targets when exporting deploy
outputs and record the SHA-256 and size of each actual payload.

On a case-insensitive control host, retain the Docker archive stream as the
canonical handoff rather than extracting the whole deploy directory. The
baseline contains distinct `LICENSE.txt` and `License.txt` files in bzip2
licence directories; a direct directory copy silently loses two files.
`docker cp <export-container>:/work/build-baseline/tmp/deploy -` emits a tar
stream that preserves both names. Write binary stdout directly to a new tar
file, keep stderr separate, and retain the command's exit status.

The verified baseline `deploy.tar` preserves 16,851 files and 9,618 symlinks.
Its full path/size/SHA-256 inventory is retained with the run logs. Validate
every member and link against that Linux inventory, not only the tar hash.
The image licence alias has an absolute target under
`/work/build-baseline/tmp/deploy/`; its versioned target is included. Restore
that original layout in a fresh Linux volume, or use the versioned members
directly. Do not treat this unchanged raw archive as freely relocatable.
The earlier macOS directory export is non-canonical and must not be used as
the complete licence handoff.

The initial durable locator is `local://firmdura-kirkstone/`, mapped on the
owner's control host to
`~/Library/Application Support/Firmdura/kirkstone-sample/`.
Its `artifacts/<run-id>/`, `logs/`, and `runs/` directories persist across
sessions. The authorized lead/reviewer use the same local account or an
explicit owner-approved transfer; no world-readable share is created.
Retain handoffs until the owner explicitly approves removal. This is local,
single-host storage, not off-host backup or a public download service.
Later release publication must provide durable public assets and corresponding
source through the separately approved release gate.

For isolated system-mode boot, use the built `qemu-system-aarch64` from the
Yocto native sysroot (or record an explicitly selected emulator version).
Set `KERNEL` and `ROOTFS` to the exported `Image` and ext4 payload, and
`RUN_ROOTFS` to a new disposable copy:

```sh
cp "$ROOTFS" "$RUN_ROOTFS"
qemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 2 -m 512 \
  -nographic -nic none -kernel "$KERNEL" \
  -drive "id=disk0,file=$RUN_ROOTFS,if=none,format=raw" \
  -device virtio-blk-pci,drive=disk0 \
  -object rng-random,filename=/dev/urandom,id=rng0 \
  -device virtio-rng-pci,rng=rng0 \
  -device virtio-serial-pci -chardev null,id=virtcon \
  -device virtconsole,chardev=virtcon \
  -append 'console=ttyAMA0 root=/dev/vda rw'
```

Use a unique disposable path and hash the frozen original before and after.
Do not use a bridged network, publish a vulnerable service, or treat successful
boot alone as library validation. The RNG and second console devices come
from the image's actual QEMU configuration; the RNG avoids the uninitialized
entropy warning observed with the earlier minimal command.
The [automated boot check](../tests/boot-reference.py) verifies target
architecture/distro, exact library bytes, its runtime version and HTTP/2
banner, the running server's library mapping, and unchanged originals.
[Testing instructions](testing.md) include the recorded invocation and its
deliberately failing wrong-library control.

## Ownership and evidence interface

| Area | Owner / purpose |
|---|---|
| `conf/`, `recipes-*` | Lead: separately consumable repair layer |
| `kas/` | Lead: shared locks, configuration and narrow container invocation |
| `meta-firmdura-tests/`, `tests/`, `docs/testing.md` | Lead: image/test-only integration and C tests |
| `.github/workflows/release.yml`, `scripts/release/`, `docs/signing.md` | STI-111: signing and strict verification |
| `scripts/bundle/`, `docs/evaluation.md` | STI-112: frozen-payload packaging |
| `scripts/vex/`, `docs/vex.md` | STI-113: actual SBOM/VEX consumer integration |
| `evidence/<run-id>/` | Owning ticket: small sanitized run records only |
| `README.md` | Lead only: integration and truthful public status |

These are reserved owned paths, not a requirement to add empty files or a
general coordinator. Each worker receives one ticket, a separate branch and
checkout, exact merged prerequisite SHAs, and explicit file ownership.
The continuous reproduction/repair trace remains with the lead.

Each run's `run.json` must contain:

- `schema_version`, `run_id`, `issue`, `status`, `started_at`, `finished_at`;
- `inputs`: exact source/configuration/test commits (or explicitly identified
  pre-commit tree hashes), external repository URLs/commits, effective
  configuration hashes, tool versions and immutable builder identity;
- `commands`: argv, working directory, timestamps, expected outcome, actual
  exit/result, raw-log locator and SHA-256;
- `artifacts`: relative path, role, variant, size, SHA-256 and durable locator;
- `results`, `limitations`, and `timing` with measured active engineering time
  separated from elapsed build/waiting time. Unknown measurements are `null`,
  with an explanation, not estimates reported as measurements.

Unavailable checks are `blocked` or `not_run`, never `passed`. Baseline and
patched source/image identities must be distinct and traceable. Record the
unmodified upstream content as well as local patch order. Keep raw scanner
JSON, including unresolved/ignored matches and the database snapshot identity.
Do not fabricate a finding or silently substitute a scanner.

The release manifest interface is a versioned JSON object with release/source
identities and an `artifacts` array. Every entry has a relative `path`, `role`,
`variant` when applicable, `size`, and `sha256`. It binds **all** deliverable
payloads but excludes itself and the later signature bundle. Signing consumes
those frozen bytes without regenerating them. STI-111 must finalize and test
this interface with the lead before another worker consumes it.

STI-110 freezes the tested image pair. Packaging/VEX/replay workers consume it
read-only and boot only disposable copies. Any relevant source, configuration,
test or payload change invalidates affected downstream results and requires
explicit reruns. Human review and exact-release approval remain mandatory.

## Licence boundary

[LICENSE](../LICENSE) applies to original Firmdura files only. It does not
relicense Poky, meta-openembedded, meta-lts-collab, libwebsockets, upstream
patches, generated source archives or image contents. Preserve their original
licences, notices, attribution and required corresponding source. A source
URL alone is not the binary redistribution plan.
