#!/usr/bin/env python3
"""
AGGREGATOR: Multi-Scanner Coverage Assessment -> DefectDojo Generic Finding

PURPOSE:
    Reads outputs from all binary scan jobs (Trivy, Syft/SBOM coverage, file
    type analysis) and produces a single DefectDojo Generic Finding whose
    severity encodes the overall coverage tier.  This finding is the input
    that Prompt 3's Rego policy evaluates for the pass/fail/warn gate.

COVERAGE TIERS:
    Full    -> severity "Info"    -> Rego: no action
    Partial -> severity "Low"     -> Rego: warning  (exit 2)
    Minimal -> severity "Medium"  -> Rego: violation (exit 1)

SIGNAL COLLECTION:
    Trivy signal    — package types and vulnerabilities in trivy-results.json
    SBOM signal     — finding severity from dd-sbom-coverage.json (Prompt 4)
    File type signal — MIME type analysis of files in the scan target directory

TIER COMPUTATION:
    Two or more "none" signals           -> Minimal
    Exactly one "none", others compensate -> Partial
    All "partial" or better, >= 1 "full"  -> Full
    All "partial"                          -> Partial

USAGE EXAMPLE:
    python3 coverage-summary.py \\
        --trivy-results trivy-results.json \\
        --sbom-coverage dd-sbom-coverage.json \\
        --scan-target-dir /tmp/scan \\
        --output dd-coverage-summary.json
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path


# ─── Signal Collection ──────────────────────────────────────────────

def collect_trivy_signal(path):
    """Parse Trivy rootfs JSON and return (signal_level, detail_string)."""
    if not path or not os.path.isfile(path):
        return "none", "trivy-results.json not found"

    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError) as exc:
        return "none", "failed to parse trivy-results.json: %s" % exc

    results = data.get("Results", [])
    if not results:
        return "none", "no recognizable packages found"

    types = set()
    vuln_count = 0
    for entry in results:
        entry_type = entry.get("Type", "")
        if entry_type:
            types.add(entry_type)
        vulns = entry.get("Vulnerabilities")
        if vulns:
            vuln_count += len(vulns)

    if not types:
        return "none", "no recognizable packages found"

    if len(types) > 1 or vuln_count > 0:
        return "full", "detected %d package type(s) (%s), %d vulnerabilities" % (
            len(types), ", ".join(sorted(types)), vuln_count)

    return "partial", "detected 1 package type (%s), 0 vulnerabilities" % (
        ", ".join(sorted(types)))


def collect_sbom_signal(path):
    """Read dd-sbom-coverage.json (Prompt 4 output) and derive signal."""
    if not path or not os.path.isfile(path):
        return "none", "dd-sbom-coverage.json not found"

    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError) as exc:
        return "none", "failed to parse dd-sbom-coverage.json: %s" % exc

    findings = data.get("findings", [])
    if not findings:
        return "none", "no findings in dd-sbom-coverage.json"

    severity = findings[0].get("severity", "").lower()
    title = findings[0].get("title", "")

    if severity == "info":
        return "full", title
    elif severity == "low":
        return "partial", title
    else:
        return "none", title or "zero components extracted"


SCANNABLE_MIMES = {
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/java-archive",
    "application/x-mach-binary",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/zip",
}

LIMITED_MIMES = {
    "application/octet-stream",
}

MAX_FILES = 50


def collect_filetype_signal(scan_dir):
    """Walk scan directory, run `file --mime-type` on up to 50 files."""
    if not scan_dir or not os.path.isdir(scan_dir):
        return "none", "scan target directory not found or empty"

    # Gather file list (up to MAX_FILES)
    file_paths = []
    for root, _dirs, files in os.walk(scan_dir):
        for name in files:
            file_paths.append(os.path.join(root, name))
            if len(file_paths) >= MAX_FILES:
                break
        if len(file_paths) >= MAX_FILES:
            break

    if not file_paths:
        return "none", "scan target directory is empty"

    total = len(file_paths)
    sampled = total >= MAX_FILES

    # Try running file(1) on each path
    scannable = 0
    limited = 0
    unrecognized = 0

    try:
        for fp in file_paths:
            result = subprocess.run(
                ["file", "--mime-type", "-b", "-L", fp],
                capture_output=True, text=True, timeout=10,
            )
            mime = result.stdout.strip().lower()
            if mime in SCANNABLE_MIMES:
                scannable += 1
            elif mime in LIMITED_MIMES:
                limited += 1
            else:
                unrecognized += 1
    except (FileNotFoundError, OSError) as exc:
        print("[coverage-summary] WARNING: file(1) command not available: %s" % exc)
        return "none", "file(1) command not available — cannot determine file types"
    except subprocess.TimeoutExpired:
        print("[coverage-summary] WARNING: file(1) command timed out")
        return "none", "file(1) command timed out"

    sample_note = " (sampled first %d files)" % MAX_FILES if sampled else ""

    if total > 0 and (scannable / total) >= 0.50:
        detail = "%d/%d files are scannable binaries%s" % (
            scannable, total, sample_note)
        return "full", detail

    if scannable > 0:
        detail = "%d/%d files are scannable binaries%s" % (
            scannable, total, sample_note)
        return "partial", detail

    detail = "0/%d files are scannable binaries (%d octet-stream, %d other)%s" % (
        total, limited, unrecognized, sample_note)
    return "none", detail


# ─── Tier Computation ───────────────────────────────────────────────

def compute_tier(trivy_signal, sbom_signal, filetype_signal):
    """Compute coverage tier from three signal levels."""
    signals = [trivy_signal, sbom_signal, filetype_signal]
    none_count = signals.count("none")
    full_count = signals.count("full")

    if none_count >= 2:
        return "minimal"

    if none_count == 1:
        return "partial"

    # none_count == 0
    if full_count >= 1:
        return "full"

    return "partial"


TIER_SEVERITY = {
    "full": "Info",
    "partial": "Low",
    "minimal": "Medium",
}


# ─── Output ─────────────────────────────────────────────────────────

def build_description(tier, trivy_signal, trivy_detail,
                      sbom_signal, sbom_detail,
                      filetype_signal, filetype_detail):
    """Build the finding description with per-scanner breakdown."""
    lines = [
        "Coverage Tier: %s" % tier.upper(),
        "",
        "Scanner Visibility:",
        "  Trivy:     %-7s -- %s" % (trivy_signal, trivy_detail),
        "  SBOM:      %-7s -- %s" % (sbom_signal, sbom_detail),
        "  File Type: %-7s -- %s" % (filetype_signal, filetype_detail),
    ]

    if tier == "minimal":
        lines += [
            "",
            "Action Required: This binary has near-zero scanner visibility. "
            "CVE-based assessment is unreliable. Before this artifact can be "
            "considered assessed, perform one of:",
            "  1. Manual security review of the binary",
            "  2. Request vendor-provided SBOM or security attestation",
            "  3. Re-scan with YARA signature rules and capability analysis "
            "when available",
            "  4. Submit a risk acceptance in DefectDojo for this finding "
            "with documented justification",
        ]

    if tier == "partial":
        lines += [
            "",
            "Note: Scanner coverage is incomplete. Results should be treated "
            "as a lower bound -- additional vulnerabilities may exist that "
            "were not detectable. Consider supplementary analysis when "
            "available.",
        ]

    return "\n".join(lines)


def build_finding(tier, description):
    """Build a single DefectDojo Generic Finding."""
    return {
        "title": "Binary Scan Coverage Assessment: %s" % tier.upper(),
        "description": description,
        "severity": TIER_SEVERITY[tier],
        "date": date.today().isoformat(),
        "active": True,
        "verified": False,
        "static_finding": True,
        "dynamic_finding": False,
        "vuln_id_from_tool": "BINARY-COVERAGE-SUMMARY",
        "tags": ["binary-scan", "scan-coverage"],
    }


def print_summary(tier, trivy_signal, trivy_detail,
                   sbom_signal, sbom_detail,
                   filetype_signal, filetype_detail):
    """Print a formatted summary for GitLab job log visibility."""
    bar = "=" * 50

    tier_display = tier.upper()
    if tier == "minimal":
        tier_display += "  !!"
    elif tier == "partial":
        tier_display += "  !"

    print()
    print(bar)
    print("  BINARY SCAN COVERAGE ASSESSMENT")
    print(bar)
    print()
    print("  Coverage Tier:  %s" % tier_display)
    print()
    print("  Trivy:          %-7s -- %s" % (trivy_signal, trivy_detail))
    print("  SBOM (Syft):    %-7s -- %s" % (sbom_signal, sbom_detail))
    print("  File Types:     %-7s -- %s" % (filetype_signal, filetype_detail))

    if tier == "minimal":
        print()
        print("  !!  Near-zero scanner visibility. CVE assessment")
        print("     is unreliable for this artifact. See pipeline")
        print("     documentation for next steps.")

    if tier == "partial":
        print()
        print("  !  Coverage is incomplete. Results are a lower bound.")
        print("     Consider supplementary analysis.")

    print()
    print(bar)
    print()


# ─── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Aggregate scan coverage signals into a DD Generic Finding"
    )
    parser.add_argument("--trivy-results",
                        help="Path to trivy-results.json")
    parser.add_argument("--sbom-coverage",
                        help="Path to dd-sbom-coverage.json (Prompt 4 output)")
    parser.add_argument("--scan-target-dir",
                        help="Path to unpacked scan directory")
    parser.add_argument("--output", required=True,
                        help="Output path for DD Generic Findings JSON")
    args = parser.parse_args()

    # Collect signals
    trivy_signal, trivy_detail = collect_trivy_signal(args.trivy_results)
    sbom_signal, sbom_detail = collect_sbom_signal(args.sbom_coverage)
    filetype_signal, filetype_detail = collect_filetype_signal(
        args.scan_target_dir)

    # Compute tier
    tier = compute_tier(trivy_signal, sbom_signal, filetype_signal)

    # Build description and finding
    description = build_description(
        tier,
        trivy_signal, trivy_detail,
        sbom_signal, sbom_detail,
        filetype_signal, filetype_detail,
    )
    finding = build_finding(tier, description)

    # Write output
    dd_output = {
        "findings": [finding],
    }

    with open(args.output, "w") as f:
        json.dump(dd_output, f, indent=2)

    # Console summary for GitLab job log
    print_summary(
        tier,
        trivy_signal, trivy_detail,
        sbom_signal, sbom_detail,
        filetype_signal, filetype_detail,
    )

    print("[coverage-summary] %s (tier: %s, severity: %s) -> %s"
          % (finding["title"], tier.upper(), finding["severity"], args.output))


if __name__ == "__main__":
    main()

# ─── Pipeline Integration ──────────────────────────────────────────
#
# coverage-summary:
#   stage: upload   # runs after scan jobs, before DD upload
#   image: python:3.11-alpine
#   needs:
#     - job: parse-binary-ref
#       artifacts: true
#     - job: trivy-binary-scan
#       artifacts: true
#     - job: sbom-coverage-check
#       artifacts: true
#   before_script:
#     - apk add --no-cache file   # for MIME type detection
#   script:
#     - python scripts/coverage-summary.py
#         --trivy-results trivy-results.json
#         --sbom-coverage dd-sbom-coverage.json
#         --scan-target-dir "$SCAN_TARGET_DIR"
#         --output dd-coverage-summary.json
#   artifacts:
#     paths:
#       - dd-coverage-summary.json
#     expire_in: 7 days
#     when: always
#
# upload-coverage-summary:
#   extends: .dd-reimport
#   stage: upload
#   needs:
#     - job: coverage-summary
#       artifacts: true
#     - job: parse-binary-ref
#       artifacts: true
#   variables:
#     SCAN_TYPE: "Generic Findings Import"
#     SCAN_FILE: dd-coverage-summary.json
