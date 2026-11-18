# SPDX-License-Identifier: MIT
FILESEXTRAPATHS:prepend := "${THISDIR}/${BPN}:"

PR:append = ".firmdura1"

SRC_URI:append = " \
    file://CVE-2026-19773-1.patch \
    file://CVE-2026-19773-2.patch \
"
