#!/usr/bin/env python3
"""
TRANSFORMER: Syft CycloneDX SBOM -> DefectDojo Generic Finding (Coverage Signal)

PURPOSE:
    Checks whether a Syft-generated SBOM contains meaningful component data
    and emits a single DefectDojo Generic Finding reflecting the SBOM layer's
    contribution to overall scan coverage.

    This finding is an intermediate artifact consumed by the coverage summary
    job (Prompt 5), which aggregates signals from multiple scanners to
    determine the final coverage tier.

COVERAGE LEVELS:
    0 components   -> severity "Medium", vuln_id "SBOM-COVERAGE-NONE"
    1-5 components -> severity "Low",    vuln_id "SBOM-COVERAGE-LOW"
    6+ components  -> severity "Info",   vuln_id "SBOM-COVERAGE-OK"

USAGE EXAMPLE:
    python3 sbom-coverage-to-dd.py \\
        --input sbom.cdx.json \\
        --output dd-sbom-coverage.json
"""
import argparse
import json
import os
import sys
from datetime import date


def get_product_name(data):
    """Extract binary/product name from CycloneDX metadata or environment."""
    try:
        name = data.get("metadata", {}).get("component", {}).get("name")
        if name:
            return name
    except (AttributeError, TypeError):
        pass

    return os.environ.get("SCAN_PRODUCT_NAME", "unknown")


def get_component_types(components):
    """Extract unique component type descriptions from CycloneDX components."""
    types = set()
    for comp in components:
        ctype = comp.get("type", "")
        if ctype:
            types.add(ctype)
    return sorted(types)


def build_finding(components, product_name, parse_error=None):
    """Build a single DefectDojo Generic Finding based on SBOM coverage."""
    count = len(components)
    today = date.today().isoformat()

    base = {
        "active": True,
        "verified": False,
        "static_finding": True,
        "dynamic_finding": False,
        "date": today,
        "tags": ["binary-scan", "sbom-coverage"],
    }

    if count == 0:
        desc = (
            "Syft extracted zero software components from the binary "
            "artifact \"%s\"." % product_name
        )
        if parse_error:
            desc += "\n\nNote: %s" % parse_error
        desc += (
            "\n\nThis typically indicates a stripped C/C++ binary, raw "
            "firmware blob, or unsupported binary format. Dependency Track "
            "analysis will return no results. The SBOM layer provides no "
            "vulnerability coverage for this artifact."
        )
        base.update({
            "title": "SBOM Coverage: No components detected",
            "severity": "Medium",
            "description": desc,
            "vuln_id_from_tool": "SBOM-COVERAGE-NONE",
        })

    elif count <= 5:
        detected_types = get_component_types(components)
        types_str = ", ".join(detected_types) if detected_types else "unknown"
        base.update({
            "title": "SBOM Coverage: Low — %d component(s) detected" % count,
            "severity": "Low",
            "description": (
                "Syft extracted only %d component(s) from \"%s\". "
                "SBOM coverage is partial — some metadata was found "
                "(likely from %s) but many dependencies may be undetected. "
                "Dependency Track analysis will have limited scope."
            ) % (count, product_name, types_str),
            "vuln_id_from_tool": "SBOM-COVERAGE-LOW",
        })

    else:
        base.update({
            "title": "SBOM Coverage: Adequate — %d components detected"
                     % count,
            "severity": "Info",
            "description": (
                "Syft extracted %d components from \"%s\". SBOM coverage "
                "is sufficient for meaningful Dependency Track analysis."
            ) % (count, product_name),
            "vuln_id_from_tool": "SBOM-COVERAGE-OK",
        })

    return base


def main():
    parser = argparse.ArgumentParser(
        description="Transform Syft CycloneDX SBOM to DD Generic Finding"
    )
    parser.add_argument("--input", required=True,
                        help="Path to Syft CycloneDX SBOM (sbom.cdx.json)")
    parser.add_argument("--output", required=True,
                        help="Output path for DD Generic Findings JSON")
    args = parser.parse_args()

    components = []
    product_name = "unknown"
    parse_error = None

    if not os.path.isfile(args.input):
        parse_error = "SBOM file not found: %s" % args.input
        print("[sbom-coverage-to-dd] %s" % parse_error)
    else:
        try:
            with open(args.input) as f:
                data = json.load(f)
            components = data.get("components", [])
            product_name = get_product_name(data)
        except (json.JSONDecodeError, ValueError) as exc:
            parse_error = "Failed to parse SBOM: %s" % exc
            print("[sbom-coverage-to-dd] %s" % parse_error)

    finding = build_finding(components, product_name, parse_error)

    dd_output = {
        "findings": [finding],
    }

    with open(args.output, "w") as f:
        json.dump(dd_output, f, indent=2)

    print("[sbom-coverage-to-dd] %s (severity: %s, components: %d) -> %s"
          % (finding["title"], finding["severity"], len(components),
             args.output))


if __name__ == "__main__":
    main()

# ─── Pipeline Integration ──────────────────────────────────────────
#
# sbom-coverage-check:
#   stage: scan   # NOTE: runs in scan stage, not upload — Prompt 5 consumes this artifact
#   image: python:3.14-alpine
#   needs:
#     - job: syft-binary-sbom
#       artifacts: true
#     - job: parse-binary-ref
#       artifacts: true
#   script:
#     - python scripts/sbom-coverage-to-dd.py --input sbom.cdx.json --output dd-sbom-coverage.json
#   artifacts:
#     paths:
#       - dd-sbom-coverage.json
#     expire_in: 7 days
#     when: always
