# Community contribution to `meta-lts-collab` (`kirkstone`)

On 2026-11-18, Firmdura submitted the `CVE-2026-19773` backport for
`libwebsockets` 4.2.2 to the `kirkstone` branch of Garmin's
[`meta-lts-collab`](https://github.com/garmin/meta-lts-collab/tree/kirkstone)
in [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283);
after upstream `PR Validation` passed, a maintainer merged it on 2026-11-20 as
[`c1af58126047932d50ffac47e925d1399c162aa3`](https://github.com/garmin/meta-lts-collab/commit/c1af58126047932d50ffac47e925d1399c162aa3).
The [contribution record](../evidence/20261118-sti114-contribution/run.json)
indexes the 2026-11-18 submission command logs, digests and timestamps. The
[paired validation record](../evidence/20261118-sti110-paired-validation/run.json)
covers the `qemuarm64` builds and runtime checks.

The contributed patches backport existing upstream `libwebsockets` commits fixing
[`CVE-2026-19773`](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)
(discovered by Maher Azzouzi working with TrendAI Zero Day Initiative). This
contribution shares a validated Yocto Kirkstone maintenance-layer backport and
does not claim original vulnerability discovery or authorship of the upstream C
fixes.

## Pre-submission community coverage check

Checked against public GitHub state at `2026-11-18T13:17:39Z` before opening a
pull request:

- **`garmin/meta-lts-collab` (`kirkstone` branch)**: branch tip remained
  `e127ed67e74ca6b7e0fdc6cbda572302886c00a0` (`2026-11-16T19:21:59Z`,
  `"build(deps-dev): bump ruff"`), identical to the locked pin in
  [`kas/common.yml`](../kas/common.yml) (`0` commits ahead, `0` behind).
- **`kirkstone` tree scan**: `0` matches for `libwebsockets`, `19773`, or
  `zdi-26-590` across all `241` non-truncated repository tree entries.
- **Open and closed pull requests and issues**: `0` matches across `--state all`
  queries in `garmin/meta-lts-collab` for `libwebsockets`, `CVE-2026-19773`,
  `ZDI-26-590`, `824151862`, `0c6cef092`, and `zdi-can-31036`.
- **`openembedded/meta-openembedded` (`kirkstone` branch)**: branch tip remained
  `ce8539c941f6fcbecaca4d16640ac105c0595589` (`2026-05-04T13:59:37Z`), carrying
  unpatched `meta-oe/recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bb`
  (`SRCREV = "8d605f0649ed1ab6d27a443c7688598ea21fdb75"`, default
  `PACKAGECONFIG = "libuv client server http2 ssl"`).

Because no equivalent `libwebsockets` recipe append or `CVE-2026-19773` repair
was present or queued, a minimal backport pull request was submitted.

## Submitted pull request and commit provenance

| Field | Value |
|---|---|
| Upstream pull request | [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283) |
| Target base | `garmin/meta-lts-collab` branch `kirkstone` (`e127ed67e74ca6b7e0fdc6cbda572302886c00a0`) |
| Fork and branch | [`firmdura/meta-lts-collab`](https://github.com/firmdura/meta-lts-collab) branch `kirkstone-libwebsockets-cve-2026-19773` |
| Contributed commit | [`e0d216d2f4884c3ad2368ac6ffc4f4a72aeb0c0c`](https://github.com/firmdura/meta-lts-collab/commit/e0d216d2f4884c3ad2368ac6ffc4f4a72aeb0c0c) (tree `cc2b0de95174dd6b896edada48da48a8cce1a08d`) |
| Commit authentication | GitHub-verified SSH `ED25519` signature and DCO `Signed-off-by` |
| Initial PR status (`2026-11-18T13:50:28Z`) | `OPEN` (`reviewDecision: REVIEW_REQUIRED`, `0` review comments) |
| Initial CI workflow run | [`actions/runs/44317715424`](https://github.com/garmin/meta-lts-collab/actions/runs/44317715424) (`PR Validation`: `action_required`, awaiting maintainer approval for first-time external fork PR) |
| Upstream CI completion (`2026-11-20T22:24:53Z`) | [`actions/runs/44317715424`](https://github.com/garmin/meta-lts-collab/actions/runs/44317715424) (`PR Validation`: `SUCCESS` across `Lint`, `Check layer`, `Build (systemd=true)`, `Build (systemd=false)`, and `Required checks pass`) |
| Upstream merge (`2026-11-20T22:30:20Z`) | `MERGED` into `kirkstone` as [`c1af58126047932d50ffac47e925d1399c162aa3`](https://github.com/garmin/meta-lts-collab/commit/c1af58126047932d50ffac47e925d1399c162aa3) (`reviewDecision: APPROVED`) |

### Layer placement, metadata rules, and patch provenance

`garmin/meta-lts-collab` activates `meta-openembedded` appends through
`BBFILES_DYNAMIC` (`openembedded-layer:${LAYERDIR}/meta-oe/*/*/*.bbappend`) in
its `conf/layer.conf` and enforces `oelint-adv` rules in `.oelint.cfg` and
`meta-lts-collab-test/scripts/oelint/rulefile.json`. Only public,
redistributable recipe and patch files were submitted:

1. **`meta-oe/recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend`**
   (`144` bytes, SHA-256
   `09915113401129ad4053d39389e899f33014e2c5e5c8cac1b01d016cc5d2a4d8`):
   prepends `${THISDIR}/${BPN}:` to `FILESEXTRAPATHS` and appends
   `CVE-2026-19773-1.patch` and `CVE-2026-19773-2.patch` to `SRC_URI`. It omits
   the sample repository's `PR:append = ".firmdura1"` (`oelint.append.protvars.PR`
   is an error in `meta-lts-collab`) and is contributed under
   `meta-lts-collab`'s Apache-2.0 repository licence.
2. **`meta-oe/recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch`**
   (`982` bytes, SHA-256
   `941c7b1651aa3e953f37de71d3c76736545eaf2d34468794bd50e80ae8b1075c`):
   backports upstream commit
   [`824151862f37bc72f46d9a3e01d5b9408d313a0b`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)
   (`Andy Green <andy@warmcat.com>`), preserving ZDI discovery attribution,
   `CVE: CVE-2026-19773`, `Upstream-Status: Backport [...]`, DCO `Signed-off-by`,
   and `libwebsockets`'s upstream MIT licence. Its unified-diff payload
   (`84b7b05d8f0b6c1f28402bb0699bef720ec90f3e24fae775e1cf41f1ff86605c`) is
   byte-identical to
   [`recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch).
3. **`meta-oe/recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch`**
   (`1,204` bytes, SHA-256
   `bfc4939b4f29c44abd2615ad4468d780c256b1ad06a04e89a85a0387f42ca048`):
   backports upstream commit
   [`0c6cef0922c531f2662e87e74e17c191fa18162b`](https://github.com/warmcat/libwebsockets/commit/0c6cef0922c531f2662e87e74e17c191fa18162b)
   (`Feng Xue <feng.xue@outlook.com>`), carrying `CVE: CVE-2026-19773`,
   `Upstream-Status: Backport [...]`, a DEP-3 `Comment:` header noting the
   `4.2.2` line-offset adjustment, and DCO `Signed-off-by`. Because both patches
   come directly from `warmcat/libwebsockets` fix commits rather than a
   downstream distribution or third-party layer, no separate `Origin:` tag is
   required under `meta-lts-collab`'s patch metadata policy. Its unified-diff
   payload (`c9d1e94f228c4670b72da3f5a6555674ea12be8c9c5c3066339c4b8d78f47767`)
   is byte-identical to
   [`recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch).

No sample-specific test recipes (`meta-firmdura-tests/`), local build scripts,
or non-public artifacts were included in the upstream pull request.

## Local checks, community CI scope, and architecture boundaries

Before pushing the fork branch, the contribution was validated locally against
`garmin/meta-lts-collab`'s pinned `requirements-dev.txt` (`oelint-adv==9.11.3`,
`ruff==0.17.5`, `yamllint==1.38.0`) in an isolated Python `3.12.15` virtual
environment:

```sh
ruff check meta-lts-collab-test/scripts
ruff format --check meta-lts-collab-test/scripts/
yamllint .github/
oelint-adv $(find . -path ./.git -prune -o \( -name '*.bb' -o -name '*.bbappend' -o -name '*.conf' \) -print)
./meta-lts-collab-test/scripts/get-bitbake-targets.py --image \
  meta-oe/recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend \
  meta-oe/recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch \
  meta-oe/recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch
```

- `ruff check`, `ruff format --check`, `yamllint`, and `oelint-adv` (including
  `meta-lts-collab`'s custom `oelint.ltscollab.backportsonly` and
  `oelint.ltscollab.upstreamstatus` rules) all exited `0` with zero errors and
  zero findings on `libwebsockets_4.2.2.bbappend` and its patches.
- `get-bitbake-targets.py --image` resolved `libwebsockets` for
  `CORE_IMAGE_EXTRA_INSTALL` (`--native` resolved empty).
- `git apply --check --whitespace=error` and `git am` applied both contributed
  patches cleanly onto upstream `warmcat/libwebsockets` commit
  `8d605f0649ed1ab6d27a443c7688598ea21fdb75` with zero fuzz, matching the
  BitBake `do_patch` and `do_qa_patch` execution recorded in the
  [paired validation evidence](../evidence/20261118-sti110-paired-validation/run.json).

### Community CI scope versus `qemuarm64` paired validation

In `garmin/meta-lts-collab`, pull requests against `kirkstone` run a gated
pipeline (`.github/workflows/pull-request.yml` -> `_common.yml`):

1. **`Lint`** (`ubuntu-22.04`): `ruff`, `yamllint`, and `oelint-adv`.
2. **`Check layer`** (`ubuntu-22.04`):
   `yocto-check-layer --without-software-layer-signature-check` against Poky
   `kirkstone` and `meta-openembedded` `kirkstone`.
3. **`Build (systemd=true)` and `Build (systemd=false)`** (self-hosted
   `yocto_build_host` KVM runners): builds `core-image-minimal` for
   `qemux86-64` with `ERROR_QA += "patch-fuzz"`, `DISTRO_FEATURES:append = " pam ptest"`,
   `CORE_IMAGE_EXTRA_INSTALL = "libwebsockets"`, and executes
   `bitbake -c testimage core-image-minimal` (`TEST_SUITES = "ping ssh ptest"`).

- **Upstream CI at submission (2026-11-18)**: GitHub Actions marked
  [run `44317715424`](https://github.com/garmin/meta-lts-collab/actions/runs/44317715424)
  as `action_required`. The first contribution from this fork needed maintainer
  approval to run on Garmin's self-hosted runners. The 2026-11-18 contribution
  record therefore lists upstream CI as `blocked` at submission time.
- **Upstream CI and merge (2026-11-20)**: After maintainer approval ran
  [run `44317715424`](https://github.com/garmin/meta-lts-collab/actions/runs/44317715424),
  all five required checks (`Lint`, `Check layer`, `Build (systemd=true)`,
  `Build (systemd=false)`, and `Required checks pass`) completed with `SUCCESS`,
  and [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283)
  was approved and merged into `kirkstone` at `2026-11-20T22:30:20Z`
  ([`c1af58126047932d50ffac47e925d1399c162aa3`](https://github.com/garmin/meta-lts-collab/commit/c1af58126047932d50ffac47e925d1399c162aa3)).
- **Architecture and test-depth separation**: `meta-openembedded`'s
  `libwebsockets_4.2.2.bb` does not inherit `ptest`, so `meta-lts-collab`'s
  `qemux86-64` `do_testimage` verifies `qemux86-64` compilation, zero-fuzz
  patching, rootfs installation under both `sysvinit` and `systemd`, QEMU boot,
  `ping`, `ssh`, and baseline `ptest-runner` invocation, **not** targeted
  `CVE-2026-19773` HTTP/2 HPACK `:path` boundary exploitation or post-attack
  HTTP/2 service liveness. Targeted before/after reproduction and incomplete-fix
  controls were verified on `qemuarm64` (`Poky 4.0.35`
  `93431249a6260da7bd29ee3ca32145d89e5b8259`) as documented in the
  [testing guide](testing.md#paired-baseline-versus-patched-candidate-validation);
  conversely, this repository has not run local `qemux86-64` `systemd`/`sysvinit`
  matrix builds.

## Pin hygiene and double-patch guard

Per [the build contract](build.md#locked-inputs), [`kas/common.yml`](../kas/common.yml)
remains locked to `garmin/meta-lts-collab` commit
`e127ed67e74ca6b7e0fdc6cbda572302886c00a0` so the reviewed `baseline` and
`patched` `qemuarm64` image pair stays reproducible and unchanged.

Because `garmin/meta-lts-collab` `kirkstone` includes
[`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283)
starting at merge commit
[`c1af58126047932d50ffac47e925d1399c162aa3`](https://github.com/garmin/meta-lts-collab/commit/c1af58126047932d50ffac47e925d1399c162aa3)
(`2026-11-20`):

- Do **not** silently advance the `meta-lts-collab` commit in
  [`kas/common.yml`](../kas/common.yml) while keeping
  [`recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend`](../recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend)
  enabled: including both layers would append `CVE-2026-19773-1.patch` and
  `CVE-2026-19773-2.patch` twice during `do_patch` and would also remove the
  unpatched `libwebsockets` `4.2.2` baseline from `kas/baseline.yml`.
- Any future update to the `meta-lts-collab` lock or retirement of the local
  repair layer requires an explicit configuration change and fresh paired build,
  SBOM, and runtime validation.
