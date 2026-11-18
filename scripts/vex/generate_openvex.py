#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate artifact-specific OpenVEX v0.2.0 documents and verify Grype positive/negative controls."""

import argparse
import hashlib
import json
import re
from pathlib import Path

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
TARGET_CVE = "CVE-2026-19773"
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
PRODUCT_PURL_RE = re.compile(r"^pkg:generic/[A-Za-z0-9._-]+@1\.0-sha256\.[0-9a-f]{64}$")
VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
VALID_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


class OpenVexError(ValueError):
    """Raised when OpenVEX generation, schema validation, or Grype control verification fails."""


def require(cond, msg):
    if not cond:
        raise OpenVexError(msg)


def validate_openvex_v020(doc):
    require(isinstance(doc, dict), "OpenVEX document must be a JSON object")
    for req_key in ("@context", "@id", "author", "timestamp", "version", "statements"):
        require(req_key in doc, f"missing required OpenVEX top-level field: {req_key}")
    require(str(doc["@context"]).startswith(OPENVEX_CONTEXT),
            f"unexpected @context: {doc.get('@context')}")
    require(isinstance(doc["@id"], str) and doc["@id"].startswith("https://"),
            "@id must be an https URI")
    require(isinstance(doc["author"], str) and bool(doc["author"].strip()), "author must be non-empty")
    require(isinstance(doc["timestamp"], str) and RFC3339_RE.match(doc["timestamp"]),
            f"invalid RFC3339 timestamp: {doc.get('timestamp')}")
    if "last_updated" in doc:
        require(isinstance(doc["last_updated"], str) and RFC3339_RE.match(doc["last_updated"]),
                f"invalid RFC3339 last_updated: {doc.get('last_updated')}")
    require(type(doc["version"]) is int and doc["version"] >= 1, "version must be a positive integer")
    stmts = doc["statements"]
    require(isinstance(stmts, list) and len(stmts) >= 1, "statements must be a non-empty array")

    fixed_products = set()
    affected_products = set()
    for idx, st in enumerate(stmts):
        require(isinstance(st, dict), f"statement[{idx}] must be an object")
        vuln = st.get("vulnerability")
        require(isinstance(vuln, dict) and isinstance(vuln.get("name"), str) and vuln["name"],
                f"statement[{idx}] missing vulnerability.name")
        products = st.get("products")
        require(isinstance(products, list) and len(products) >= 1,
                f"statement[{idx}] must list at least one product")
        status = st.get("status")
        require(status in VALID_STATUSES, f"statement[{idx}] invalid status: {status}")
        if "timestamp" in st:
            require(isinstance(st["timestamp"], str) and RFC3339_RE.match(st["timestamp"]),
                    f"statement[{idx}] invalid timestamp")
        if status == "affected":
            require(isinstance(st.get("action_statement"), str) and bool(st["action_statement"].strip()),
                    f"statement[{idx}] status='affected' requires action_statement per OpenVEX v0.2.0")
        if status == "not_affected":
            has_just = st.get("justification") in VALID_JUSTIFICATIONS
            has_imp = isinstance(st.get("impact_statement"), str) and bool(st["impact_statement"].strip())
            require(has_just or has_imp,
                    f"statement[{idx}] status='not_affected' requires justification or impact_statement")
        for p in products:
            pid = p.get("@id") if isinstance(p, dict) else None
            require(isinstance(pid, str) and PRODUCT_PURL_RE.match(pid),
                    f"statement[{idx}] product @id must be an artifact-hash-bound pkg:generic PURL, got {pid!r}")
            require("subcomponents" not in p or not p["subcomponents"],
                    "do not invent subcomponent PURLs absent from Yocto Kirkstone SPDX")
            if status == "fixed":
                fixed_products.add(pid)
            elif status == "affected":
                affected_products.add(pid)

    require(bool(fixed_products), "OpenVEX document must contain a fixed statement for the patched artifact")
    require(not (fixed_products & affected_products),
            "fixed and affected product PURLs must be strictly disjoint")
    return True


def build_openvex_document(*, baseline_manifest_path, patched_manifest_path, document_id, timestamp, evidence_url):
    b_man = json.loads(baseline_manifest_path.read_text())
    p_man = json.loads(patched_manifest_path.read_text())
    b_root = b_man["output"]["root_source_package"]
    p_root = p_man["output"]["root_source_package"]
    b_purl = b_root["grype_openvex_product_purl"]
    p_purl = p_root["grype_openvex_product_purl"]
    require(b_purl != p_purl, "baseline and patched OpenVEX product PURLs must be distinct")

    doc = {
        "@context": OPENVEX_CONTEXT,
        "@id": document_id,
        "author": "Firmdura",
        "role": "Document Creator",
        "timestamp": timestamp,
        "last_updated": timestamp,
        "version": 1,
        "tooling": "firmdura-generate-openvex-v1",
        "statements": [
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-19773",
                    "name": TARGET_CVE,
                    "description": "libwebsockets HTTP/2 HPACK :path header parsing out-of-bounds heap write in lws_frag_append",
                    "aliases": ["ZDI-26-590"],
                },
                "timestamp": timestamp,
                "products": [
                    {
                        "@id": p_purl,
                        "hashes": {"sha256": p_root["rootfs_sha256"]},
                    }
                ],
                "status": "fixed",
                "status_notes": (
                    f"Repaired in Firmdura reference image {p_root['name']} "
                    f"(rootfs sha256:{p_root['rootfs_sha256']}) via recipes-connectivity/libwebsockets/"
                    f"libwebsockets_4.2.2.bbappend backporting upstream commits "
                    f"824151862f37bc72f46d9a3e01d5b9408d313a0b (pre-write max_http_header_data guard in "
                    f"lws_frag_append) and 0c6cef0922c531f2662e87e74e17c191fa18162b (post-bump bounds "
                    f"check in lws_parse_urldecode). Validated on system-mode qemuarm64 with target "
                    f"security, normal HTTP/2, ptest, and incomplete-fix controls ({evidence_url}). "
                    f"Applies strictly to this exact reference image digest and not to external or "
                    f"customer firmware."
                ),
            },
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-19773",
                    "name": TARGET_CVE,
                    "aliases": ["ZDI-26-590"],
                },
                "timestamp": timestamp,
                "products": [
                    {
                        "@id": b_purl,
                        "hashes": {"sha256": b_root["rootfs_sha256"]},
                    }
                ],
                "status": "affected",
                "action_statement": (
                    f"Do not deploy intentionally vulnerable evaluation baseline {b_root['name']} "
                    f"(rootfs sha256:{b_root['rootfs_sha256']}) or expose it to untrusted networks; "
                    f"evaluate the repaired reference image (sha256:{p_root['rootfs_sha256']}) or "
                    f"apply recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend."
                ),
            },
        ],
    }
    validate_openvex_v020(doc)
    return doc


def summarize_grype_report(report_path):
    rep = json.loads(report_path.read_text())
    active = rep.get("matches", [])
    ignored = rep.get("ignoredMatches", [])
    active_target = [m["artifact"]["name"] for m in active if m["vulnerability"]["id"] == TARGET_CVE]
    ignored_target = []
    for im in ignored:
        if im["vulnerability"]["id"] == TARGET_CVE:
            ignored_target.append({
                "package": im["artifact"]["name"],
                "applied_ignore_rules": im.get("appliedIgnoreRules", []),
            })
    return {
        "file": report_path.name,
        "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "grype_version": rep["descriptor"]["version"],
        "db_from": rep["descriptor"]["db"]["status"]["from"],
        "db_built": rep["descriptor"]["db"]["status"]["built"],
        "active_match_count": len(active),
        "ignored_match_count": len(ignored),
        "active_cve_2026_19773_packages": sorted(active_target),
        "ignored_cve_2026_19773": sorted(ignored_target, key=lambda x: x["package"]),
    }


def verify_control_matrix(*, patched_purl, aux_base_unfiltered, aux_patch_unfiltered,
                          aux_patch_vex, aux_base_vex, stock_base_unfiltered,
                          stock_patch_unfiltered, stock_patch_vex, stock_base_vex):
    abu = summarize_grype_report(aux_base_unfiltered)
    apu = summarize_grype_report(aux_patch_unfiltered)
    apv = summarize_grype_report(aux_patch_vex)
    abv = summarize_grype_report(aux_base_vex)
    sbu = summarize_grype_report(stock_base_unfiltered)
    spu = summarize_grype_report(stock_patch_unfiltered)
    spv = summarize_grype_report(stock_patch_vex)
    sbv = summarize_grype_report(stock_base_vex)

    expected_pkgs = ["libwebsockets-evlib-uv", "libwebsockets-testapps", "libwebsockets18"]
    require(abu["active_cve_2026_19773_packages"] == expected_pkgs and abu["ignored_match_count"] == 0,
            f"aux baseline unfiltered did not report expected 3 active target matches: {abu}")
    require(apu["active_cve_2026_19773_packages"] == expected_pkgs and apu["ignored_match_count"] == 0,
            f"aux patched unfiltered did not report expected 3 active target matches: {apu}")

    # Positive control: patched + OpenVEX suppresses ONLY CVE-2026-19773 via fixed rule on patched_purl
    require(apv["active_cve_2026_19773_packages"] == [],
            f"positive VEX control failed: patched still has active CVE-2026-19773: {apv}")
    require([x["package"] for x in apv["ignored_cve_2026_19773"]] == expected_pkgs,
            f"positive VEX control missing 3 ignored CVE-2026-19773 entries: {apv}")
    require(apv["active_match_count"] == apu["active_match_count"] - 3,
            "positive VEX control suppressed unrelated findings")
    for entry in apv["ignored_cve_2026_19773"]:
        rules = entry["applied_ignore_rules"]
        require(any(r.get("namespace") == "vex" and r.get("vex-status") == "fixed" for r in rules),
                f"ignored match lacks fixed VEX rule provenance: {entry}")

    # Mandatory negative control: vulnerable baseline + THAT SAME patched OpenVEX MUST STILL REPORT CVE-2026-19773
    require(abv["active_cve_2026_19773_packages"] == expected_pkgs and len(abv["ignored_cve_2026_19773"]) == 0,
            f"NEGATIVE CONTROL FAILED: patched OpenVEX suppressed baseline finding: {abv}")
    require(abv["active_match_count"] == abu["active_match_count"],
            "negative VEX control altered baseline active match count")

    # Stock DB scans preserve all stock matches cleanly
    for s in (sbu, spu, spv, sbv):
        require(s["active_cve_2026_19773_packages"] == [] and s["active_match_count"] == sbu["active_match_count"],
                f"unexpected stock DB scan drift: {s}")

    return {
        "status": "verified",
        "patched_product_purl": patched_purl,
        "auxiliary_test_db_controls": {
            "baseline_unfiltered": abu,
            "patched_unfiltered": apu,
            "patched_with_vex_positive_control": apv,
            "baseline_with_patched_vex_negative_control": abv,
        },
        "stock_db_scans": {
            "baseline_unfiltered": sbu,
            "patched_unfiltered": spu,
            "patched_with_vex": spv,
            "baseline_with_patched_vex": sbv,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate")
    gen.add_argument("--baseline-spdx-manifest", required=True, type=Path)
    gen.add_argument("--patched-spdx-manifest", required=True, type=Path)
    gen.add_argument("--document-id", default="https://github.com/firmdura/meta-firmdura-kirkstone/vex/20261118-cve-2026-19773-v1")
    gen.add_argument("--timestamp", default="2026-11-18T14:50:00Z")
    gen.add_argument("--evidence-url", default="https://github.com/firmdura/meta-firmdura-kirkstone/blob/b3f34157700a5547f5829ed9124779bcf1f4587e/evidence/20261118-sti110-paired-validation/run.json")
    gen.add_argument("--output", required=True, type=Path)

    ver = sub.add_parser("verify-scans")
    ver.add_argument("--openvex", required=True, type=Path)
    ver.add_argument("--aux-baseline-unfiltered", required=True, type=Path)
    ver.add_argument("--aux-patched-unfiltered", required=True, type=Path)
    ver.add_argument("--aux-patched-vex", required=True, type=Path)
    ver.add_argument("--aux-baseline-vex", required=True, type=Path)
    ver.add_argument("--stock-baseline-unfiltered", required=True, type=Path)
    ver.add_argument("--stock-patched-unfiltered", required=True, type=Path)
    ver.add_argument("--stock-patched-vex", required=True, type=Path)
    ver.add_argument("--stock-baseline-vex", required=True, type=Path)
    ver.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    if args.cmd == "generate":
        doc = build_openvex_document(
            baseline_manifest_path=args.baseline_spdx_manifest,
            patched_manifest_path=args.patched_spdx_manifest,
            document_id=args.document_id,
            timestamp=args.timestamp,
            evidence_url=args.evidence_url,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(doc, indent=2) + "\n"
        args.output.write_text(raw)
        print(json.dumps({
            "status": "generated",
            "output": str(args.output),
            "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "fixed_product": doc["statements"][0]["products"][0]["@id"],
            "affected_product": doc["statements"][1]["products"][0]["@id"],
        }, indent=2))
    else:
        vex_doc = json.loads(args.openvex.read_text())
        validate_openvex_v020(vex_doc)
        patched_purl = next(
            s["products"][0]["@id"] for s in vex_doc["statements"] if s["status"] == "fixed"
        )
        summary = verify_control_matrix(
            patched_purl=patched_purl,
            aux_base_unfiltered=args.aux_baseline_unfiltered,
            aux_patch_unfiltered=args.aux_patched_unfiltered,
            aux_patch_vex=args.aux_patched_vex,
            aux_base_vex=args.aux_baseline_vex,
            stock_base_unfiltered=args.stock_baseline_unfiltered,
            stock_patch_unfiltered=args.stock_patched_unfiltered,
            stock_patch_vex=args.stock_patched_vex,
            stock_base_vex=args.stock_baseline_vex,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps({"status": "verified", "patched_product_purl": patched_purl}, indent=2))


if __name__ == "__main__":
    main()
