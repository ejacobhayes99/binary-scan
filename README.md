# Binary Scan

----

Binary Scan is a [GitLab CI/CD] pipeline that scans standalone binary artifacts
for vulnerabilities and malware using [Trivy], [Syft], and [ClamAV], uploads
results to [DefectDojo] and [Dependency Track], and runs the [Policy Gate]
policy engine for a **PASS/FAIL gate decision** based on scan coverage
confidence.

The pipeline is defined entirely by reusable [Templates] — the local
`.gitlab-ci.yml` is a single `include:` directive:

```yaml
include:
  - project: 'develop/templates'
    ref: main
    file: 'ci/pipelines/binary-scan.yml'
```

DefectDojo is the central findings store — Trivy and Dependency Track results
are reimported on every run with `close_old_findings=true`, so DefectDojo always
reflects the current state of the artifact.

----

## Quick Start

Set the `BINARY_REF` variable to point at the binary you want to scan.
Three input formats are supported:

```
# HTTPS URL — direct download link
BINARY_REF=https://gitlab.example.com/api/v4/projects/42/packages/generic/myapp/1.0/myapp-linux-amd64.tar.gz

# GitLab Package Registry shorthand — project-id:package:version:filename
BINARY_REF=42:myapp:1.0:myapp-linux-amd64.tar.gz

# Filesystem path (requires runner mount)
BINARY_REF=/mnt/scan-inbox/firmware-v3.bin
```

**Input constraints:**

| Format | Constraint |
|--------|-----------|
| HTTPS URL | Must start with `https://`. Downloads are limited to 1 GB with a 5-minute timeout and at most 5 redirects. If the URL points at a private GitLab package registry, set `GITLAB_TOKEN`. |
| GitLab shorthand | Fields (package, version, filename) may only contain alphanumerics, hyphens, dots, and underscores. |
| Filesystem path | Must be an absolute path starting with `/`. |

**Trigger via GitLab UI:** Go to **Build > Pipelines > Run Pipeline**, add
variable `BINARY_REF` with one of the formats above.

**Trigger via API:**

```bash
curl -X POST "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/pipeline" \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"ref":"main","variables":[{"key":"BINARY_REF","value":"42:myapp:1.0:myapp-linux-amd64.tar.gz"}]}'
```

**Trigger from another pipeline:**

```yaml
trigger-binary-scan:
  trigger:
    project: develop/binary-scan
    branch: main
  variables:
    BINARY_REF: "42:myapp:1.0:myapp-linux-amd64.tar.gz"
```

## Pipeline Stages

| Stage | Job | What It Does |
|-------|-----|-------------|
| **init** | `parse-binary-ref` | Parses `BINARY_REF`, downloads/copies the artifact, unpacks archives, writes `scan.env` dotenv |
| **scan** | `trivy-binary-scan` | Scans the unpacked binary with [Trivy] for CVEs |
| **scan** | `syft-binary-sbom` | Generates a CycloneDX SBOM with [Syft] and uploads to [Dependency Track] |
| **scan** | `sbom-coverage-check` | Evaluates SBOM coverage signal for the coverage guardrail |
| **scan** | `clamav-scan` | Scans the unpacked binary for viruses/malware with [ClamAV] |
| **upload** | `upload-trivy` | Reimports Trivy results into DefectDojo |
| **upload** | `sync-dt-to-defectdojo` | Polls DT for analysis, exports FPF findings, uploads to DefectDojo |
| **upload** | `coverage-summary` | Computes coverage tier from Trivy, SBOM, and file type signals |
| **upload** | `upload-coverage-summary` | Uploads coverage assessment to DefectDojo as a finding |
| **upload** | `clamav-dd-import` | Transforms ClamAV results and reimports to DefectDojo |
| **report** | `export-findings` | Exports all findings for the product from DefectDojo API |
| **report** | `generate-report` | Generates an HTML report via DefectDojo's Report Builder |
| **report** | `enrich-epss` | Enriches findings with EPSS scores from FIRST.org |
| **report** | `enrich-kev` | Enriches findings with CISA Known Exploited Vulnerabilities data |
| **policy-gate** | `policy-gate` | Runs Policy Gate policy evaluation including the coverage guardrail |

## Scanner Coverage

| File Type | Trivy CVEs | Syft SBOM | ClamAV Malware | Expected Coverage Tier |
|---|---|---|---|---|
| Go binary (not stripped) | Good | Good | Yes | Full |
| Java .jar / .war | Good | Good | Yes | Full |
| Rust binary (cargo-auditable) | Moderate | Good | Yes | Full |
| .NET exe/dll | Moderate | Moderate | Yes | Partial |
| Python (PyInstaller) | Moderate | Moderate | Yes | Partial |
| .deb / .rpm package | Good (unpacked) | Good (unpacked) | Yes | Full |
| .msi / .cab installer | Moderate (unpacked) | Moderate (unpacked) | Yes | Partial |
| AppImage / Snap (.squashfs) | Moderate (unpacked) | Moderate (unpacked) | Yes | Partial |
| Stripped C/C++ | Very low | Near zero | Yes | Minimal (guardrail fires) |
| Firmware .bin | Moderate if rootfs | Low | Yes | Partial or Minimal |
| Raw binary blob | Near zero | Zero | Yes | Minimal (guardrail fires) |

ClamAV scans every artifact regardless of type. For binaries where Trivy and
Syft have near-zero visibility (stripped C/C++, raw blobs), ClamAV malware
detection is the primary security signal.

Archives and installer packages are automatically extracted before scanning —
coverage depends on the contents inside.

## Required CI/CD Variables

Configure these in **Settings > CI/CD > Variables**:

| Variable | Required/Optional | Description |
|----------|------------------|-------------|
| `BINARY_REF` | Required | Binary to scan (URL, shorthand, or path) |
| `DEFECTDOJO_URL` | Required | DefectDojo base URL |
| `DEFECTDOJO_TOKEN` | Required | DefectDojo API token (should be masked) |
| `DEFECTDOJO_USER` | Required | DefectDojo web UI username for report generation |
| `DEFECTDOJO_PASS` | Required | DefectDojo web UI password for report generation (should be masked) |
| `DEPENDENCY_TRACK_URL` | Required | Dependency Track API base URL |
| `DT_API_TOKEN` | Required | Dependency Track API key (should be masked) |
| `DEFECTDOJO_PRODUCT_TYPE` | Optional | DefectDojo product type (default: `Research and Development`) |
| `GITLAB_TOKEN` | Optional | GitLab PAT for private package registry downloads |
| `POLL_INTERVAL` | Optional | Seconds between Dependency Track polling attempts (default: `5`) |
| `POLL_MAX_ATTEMPTS` | Optional | Maximum polling attempts before timeout (default: `60`) |

### Policy Gate Variables

Policy Gate variables are set automatically by the pipeline templates. See
[Policy Gate configuration] for the full list of `POLICY_GATE_*` environment
variables if you need to override defaults.

## How It Works

### 1. Init

The `parse-binary-ref` job parses the `BINARY_REF` variable to determine the
input type (URL, GitLab shorthand, or filesystem path), downloads or copies the
artifact, and unpacks archives if detected. The unpacked workspace and a
`scan.env` dotenv file are passed as artifacts to all downstream jobs.

**Supported archive formats** are automatically detected by MIME type:
`.zip`, `.tar.gz`/`.tgz`, `.tar.xz`, `.msi`, `.cab`, `.deb`, `.rpm`,
`.squashfs` (AppImage/Snap). Single binaries (non-archive) are scanned
directly without unpacking.

**Archive safety limits:**

| Limit | Value | Reason |
|-------|-------|--------|
| Max download size | 1024 MB | Rejects oversized downloads before extraction |
| Max unpacked size | 2048 MB | Prevents disk exhaustion from decompression bombs |
| Max file count | 10,000 | Prevents inode exhaustion and excessive scan time |
| Path traversal | Rejected | Rejects archive entries containing `../` or absolute paths |

### 2. Scan

Four jobs run in parallel:

- **`trivy-binary-scan`** — Runs [Trivy] against the unpacked workspace to
  detect known CVEs in embedded packages and libraries.

- **`syft-binary-sbom`** — Generates a CycloneDX SBOM with [Syft] and uploads
  it to [Dependency Track] for component analysis.

- **`sbom-coverage-check`** — Evaluates the SBOM for coverage signal (component
  count, recognized file types) used by the coverage guardrail.

- **`clamav-scan`** — Runs [ClamAV] against the unpacked workspace to detect
  known viruses and malware signatures.

### 3. Upload

- **`upload-trivy`** — Reimports Trivy results into DefectDojo using the
  reimport API. `auto_create_context=true` creates the product, engagement,
  and test if they don't exist. `close_old_findings=true` marks stale findings
  as inactive.

- **`sync-dt-to-defectdojo`** — Polls Dependency Track until BOM processing and
  vulnerability analysis complete, exports findings in FPF format, and uploads
  them to DefectDojo.

- **`coverage-summary`** — Aggregates coverage signals from Trivy (package
  detection), Syft (SBOM components), and file type recognition into a
  coverage tier assessment.

- **`upload-coverage-summary`** — Uploads the coverage assessment to DefectDojo
  as a finding so it is visible in reports and available to Policy Gate.

- **`clamav-dd-import`** — Transforms ClamAV scan output into DefectDojo
  Generic Findings format and reimports. Configured with `allow_failure: true`.

### 4. Report and Enrichment

Four jobs run in parallel:

- **`export-findings`** — Exports all findings for the product from the
  DefectDojo REST API with pagination.

- **`generate-report`** — Logs into the DefectDojo web UI and generates an
  HTML report via the Report Builder.

- **`enrich-epss`** — Downloads current EPSS scores and patches DefectDojo
  findings with EPSS data for risk-based policy evaluation. Scoped to the
  current engagement using the engagement ID from `import-response.json`.
  Falls back to product-level scope if the file is missing or lacks an
  engagement ID.

- **`enrich-kev`** — Tags findings that match CISA Known Exploited
  Vulnerabilities for policy evaluation. Scoped to the current engagement
  using the engagement ID from `import-response.json`. Falls back to
  product-level scope if the file is missing or lacks an engagement ID.

### 5. Policy Gate

The `policy-gate` job runs [Policy Gate] against the product's findings.
Policy Gate evaluates all Rego policies — including the **coverage guardrail**
— and produces a PASS/FAIL decision with an HTML report. The job is configured
with `allow_failure: true` for phased rollout.

### Coverage Guardrail

The pipeline assesses scan coverage across three signals (Trivy package detection,
SBOM component extraction, file type recognition) and assigns a tier:

| Tier | Severity | Pipeline Result | Meaning |
|------|----------|----------------|---------|
| **Full** | Info | Pass | All scanners had meaningful visibility |
| **Partial** | Low | Warning (exit 2) | Some scanners had limited visibility; results are a lower bound |
| **Minimal** | Medium | Fail (exit 1) | Near-zero CVE scanner visibility; binary cannot be considered assessed for vulnerabilities |

Even at Minimal coverage, ClamAV malware scanning still runs and provides a
meaningful security signal — confirming whether the artifact contains known
malware even when CVE assessment is unreliable.

When the pipeline fails with Minimal coverage, see
[`docs/coverage-guardrail-runbook.md`](docs/coverage-guardrail-runbook.md) for
remediation options.

## Pipeline Artifacts

| Job | Artifact | Description |
|-----|----------|-------------|
| `parse-binary-ref` | `scan-workspace/unpacked/` | Unpacked binary workspace (expires after 2 hours) |
| `trivy-binary-scan` | `trivy-results.json` | Raw Trivy scan output |
| `syft-binary-sbom` | `sbom.cdx.json` | CycloneDX SBOM from Syft |
| `syft-binary-sbom` | `sbom-meta.json` | SBOM metadata for coverage check |
| `syft-binary-sbom` | `dt-upload-response.json` | Dependency Track upload response |
| `sbom-coverage-check` | `dd-sbom-coverage.json` | SBOM coverage signal assessment |
| `upload-trivy` | `import-response.json` | DefectDojo reimport response |
| `sync-dt-to-defectdojo` | `dt-findings-fpf.json` | Dependency Track findings in FPF format |
| `sync-dt-to-defectdojo` | `dt-defectdojo-import-response.json` | DefectDojo reimport response for DT findings |
| `clamav-scan` | `clamav-results.txt` | Raw ClamAV scan output |
| `clamav-dd-import` | `dd-clamav-findings.json` | Transformed DD Generic Findings |
| `clamav-dd-import` | `clamav-import-response.json` | DefectDojo reimport response |
| `coverage-summary` | `dd-coverage-summary.json` | Coverage tier assessment |
| `export-findings` | `findings.json` | All findings for the product from DefectDojo |
| `generate-report` | `public/report.html` | DefectDojo HTML report (exposed in MR) |
| `policy-gate` | `output/report.html` | Policy Gate PASS/FAIL policy report |
| `policy-gate` | `output/decisions.json` | Policy evaluation results |
| `policy-gate` | `output/findings.json` | Policy Gate-exported findings |
| `policy-gate` | `output/metrics.txt` | Violation/warning counts |

## Project Structure

```
binary-scan/
├── .gitlab-ci.yml                          # Single include from templates
├── docs/
│   └── coverage-guardrail-runbook.md       # Remediation guide for Minimal coverage
└── README.md
```

Binary Scan uses the same shared templates, DefectDojo central findings store,
Dependency Track SBOM analysis, EPSS/KEV enrichment, and Policy Gate evaluation
as [Container Scan](../container-scan) and [Repo Scan](../repo-scan). The
pipeline definition, scanner configurations, and all shared jobs live in the
[Templates] project.

| Repository | Role |
|------------|------|
| [Templates] | Shared CI/CD job templates |
| [Policy Gate] | Rego policy engine and HTML report generator |
| [Container Scan](../container-scan) | Container image scanning pipeline |
| [Repo Scan](../repo-scan) | Source code and dependency scanning pipeline |

[Trivy]: https://aquasecurity.github.io/trivy/
[Syft]: https://github.com/anchore/syft
[ClamAV]: https://www.clamav.net/
[DefectDojo]: https://www.defectdojo.com/
[Dependency Track]: https://dependencytrack.org/
[Policy Gate]: https://github.com/ejacobhayes99/policy-gate
[GitLab CI/CD]: https://docs.gitlab.com/ee/ci/
[Templates]: https://github.com/ejacobhayes99/templates
[Policy Gate configuration]: https://github.com/ejacobhayes99/policy-gate/blob/main/docs/CONFIGURATION.md
