# Coverage Guardrail Runbook

## What Happened

The binary-scan pipeline scanned a binary artifact and determined that its
CVE scanning tools had near-zero visibility into the binary's contents. The
policy engine failed the pipeline to prevent an unassessed binary from
being treated as secure.

Note that ClamAV malware scanning still ran successfully even at Minimal
coverage. The guardrail specifically reflects CVE/SBOM scanner visibility —
ClamAV provides an independent malware detection signal regardless of
coverage tier.

## How to Identify This Failure

**Pipeline job log:** The `coverage-summary` job prints a formatted banner
showing the coverage tier and per-scanner breakdown. Look for
`Coverage Tier:  MINIMAL  !!` in the job output.

**Policy-gate HTML report:** Download the `output/report.html` artifact from
the `policy-gate` job. The violation appears under the
`binary_scan_coverage` policy with message:
`Minimal scan coverage — binary artifact has near-zero scanner visibility`.

**DefectDojo:** Search for findings with `vuln_id_from_tool` =
`BINARY-COVERAGE-SUMMARY` and severity `Medium` in the product corresponding
to the scanned binary.

## Why This Happens

**Stripped C/C++ binary.** The compiler stripped debug symbols and metadata.
Trivy can't identify packages, Syft can't extract components. This is the
most common cause.

**Raw firmware blob.** The binary is a firmware image without a recognizable
filesystem structure. Trivy can't parse it as a rootfs and Syft finds no
package manifests.

**Unsupported binary format.** The binary uses a format or packaging method
that Trivy and Syft don't recognize (e.g., custom embedded formats,
encrypted binaries, proprietary container formats).

## What To Do

### Option A: Accept the risk in DefectDojo

If you've reviewed the binary through other means (vendor attestation,
manual analysis, prior assessment) and are comfortable with the risk:

1. Open DefectDojo and find the product for this binary
2. Find the finding with `vuln_id_from_tool` = `BINARY-COVERAGE-SUMMARY`
3. Set the finding status to **Risk Accepted** with a justification note
   explaining why the binary is acceptable despite low scan coverage
4. Re-run the pipeline — the risk acceptance causes policy-gate to skip
   this finding

### Option B: Provide a vendor SBOM

If the binary vendor provides a CycloneDX or SPDX SBOM:

1. Upload the vendor SBOM to Dependency Track manually for this project
   (via the DT web UI under the project's **Components** tab)
2. This populates DT with component data that gets synced to DefectDojo
   on the next scan
3. Re-run the pipeline — the SBOM signal should improve to Partial or Full

### Option C: Wait for additional scanning tools

Phase Beta adds YARA-X signature scanning and DIE packer detection. Phase
Gamma adds capa capability analysis. These future tools will provide
security assessment for binaries that CVE scanning can't cover. If the
binary is not time-critical, revisit after these tools are deployed.

### Option D: Request manual security review

Submit the binary for manual reverse engineering or security assessment
through your organization's security review process. Document the review
outcome in DefectDojo as a note on the product or engagement.

## What NOT To Do

- **Do NOT modify the Rego policy** to suppress the coverage finding. The
  guardrail exists to prevent blind spots in binary assessment.

- **Do NOT mark the finding as False Positive.** It is not a false
  positive — the scan coverage genuinely is minimal. Use **Risk Accepted**
  instead, which requires a justification.

- **Do NOT disable** the `coverage-summary` or `upload-coverage-summary`
  jobs in the pipeline. This hides the coverage gap without addressing it.

## FAQ

**Q: The pipeline failed but Trivy DID find some vulnerabilities. Why is
coverage still Minimal?**

A: Coverage tier is based on scanner visibility across all three signals
(Trivy package detection, SBOM component extraction, and file type
recognition). Trivy may find a few vulnerabilities by pattern matching
without fully understanding the binary's dependency tree. A few hits
doesn't mean comprehensive coverage.

**Q: Can I change the coverage thresholds?**

A: The thresholds are in `scripts/coverage-summary.py` (tier computation)
and `scripts/sbom-coverage-to-dd.py` (SBOM component count thresholds of
0/5/6+). Adjust these if your organization has different risk tolerance,
but document the change and the rationale.

**Q: If coverage is Minimal, was the binary scanned for anything at all?**

A: Yes. ClamAV malware scanning runs unconditionally and checks the artifact
against its full virus signature database. A Minimal coverage tier means CVE
scanners (Trivy, Syft) couldn't identify components — it does not mean the
binary was completely unexamined. Check the `clamav-scan` job output to
confirm the malware scan completed.

**Q: Does this affect container-scan or repo-scan?**

A: No. The coverage guardrail policy only evaluates findings with
`vuln_id_from_tool` starting with `BINARY-COVERAGE-` and tagged
`scan-coverage`. Container-scan and repo-scan never produce these findings.

**Q: A binary that previously passed is now failing. What changed?**

A: Most likely the binary was rebuilt and the new version has different
metadata (e.g., stripped where it wasn't before, or a dependency manager
change affected Syft detection). Compare the SBOM outputs between the
passing and failing runs by downloading the `sbom.cdx.json` artifacts
from both pipeline runs.
