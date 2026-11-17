# SPDX-License-Identifier: MIT
require recipes-core/images/core-image-minimal.bb

SUMMARY = "Isolated Firmdura qemuarm64 evaluation image, not production firmware"
IMAGE_BASENAME = "firmdura-reference-${FIRMDURA_VARIANT}"
IMAGE_INSTALL:append = " libwebsockets libwebsockets-testapps ptest-runner"
