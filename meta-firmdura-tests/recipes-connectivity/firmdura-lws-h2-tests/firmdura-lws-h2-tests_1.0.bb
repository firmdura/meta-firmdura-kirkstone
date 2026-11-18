# SPDX-License-Identifier: MIT
SUMMARY = "Target HTTP/2 HPACK boundary and normal-path regression tests for CVE-2026-19773"
DESCRIPTION = "Test-only C harness exercising libwebsockets HTTP/2 HPACK :path parsing, normal HTTP/2 request handling, and incomplete-fix boundary controls."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

DEPENDS = "libwebsockets"
RDEPENDS:${PN} += "libwebsockets"

SRC_URI = " \
    file://firmdura-h2-cve-2026-19773.c \
    file://run-ptest \
"

S = "${WORKDIR}"

inherit pkgconfig ptest

do_compile() {
    ${CC} ${CFLAGS} -Wall -Wextra -Werror \
        $(pkg-config --cflags libwebsockets) \
        ${WORKDIR}/firmdura-h2-cve-2026-19773.c \
        -o ${B}/firmdura-h2-cve-2026-19773 \
        ${LDFLAGS} $(pkg-config --libs libwebsockets) -ldl
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${B}/firmdura-h2-cve-2026-19773 ${D}${bindir}/firmdura-h2-cve-2026-19773
}

do_install_ptest() {
    install -m 0755 ${WORKDIR}/run-ptest ${D}${PTEST_PATH}/run-ptest
}
