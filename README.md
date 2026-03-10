# Binary Scan

----

Binary Scan is a [GitLab CI/CD] pipeline that scans standalone binary artifacts
for vulnerabilities using [Trivy] and [Syft], uploads results to [DefectDojo]
and [Dependency Track], and runs the [Policy Gate] policy engine for a
**PASS/FAIL gate decision** based on scan coverage confidence.

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

## What Gets Scanned

| File Type | Trivy CVEs | Syft SBOM | Expected Coverage Tier |
|---|---|---|---|
| Go binary (not stripped) | Good | Good | Full |
| Java .jar / .war | Good | Good | Full |
| Rust binary (cargo-auditable) | Moderate | Good | Full |
| .NET exe/dll | Moderate | Moderate | Partial |
| Python (PyInstaller) | Moderate | Moderate | Partial |
| .deb / .rpm package | Good (unpacked) | Good (unpacked) | Full |
| .msi / .cab installer | Moderate (unpacked) | Moderate (unpacked) | Partial |
| AppImage / Snap (.squashfs) | Moderate (unpacked) | Moderate (unpacked) | Partial |
| Stripped C/C++ | Very low | Near zero | Minimal (guardrail fires) |
| Firmware .bin | Moderate if rootfs | Low | Partial or Minimal |
| Raw binary blob | Near zero | Zero | Minimal (guardrail fires) |

Archives and installer packages are automatically extracted before scanning —
coverage depends on the contents inside.

## Pipeline Stages

| Stage | Jobs | What It Does |
|-------|------|-------------|
| **init** | `parse-binary-ref` | Parses `BINARY_REF`, downloads/copies the artifact, unpacks archives, writes `scan.env` dotenv for downstream jobs |
| **scan** | `trivy-binary-scan`, `syft-binary-sbom`, `sbom-coverage-check` | Scans the unpacked binary with Trivy (CVEs) and Syft (SBOM), evaluates SBOM coverage signal |
| **upload** | `upload-trivy`, `sync-dt-to-defectdojo`, `coverage-summary`, `upload-coverage-summary` | Reimports scan results into DefectDojo; syncs Dependency Track findings; computes and uploads coverage assessment |
| **report** | `export-findings`, `generate-report`, `enrich-epss`, `enrich-kev` | Exports findings, generates HTML report, enriches with EPSS scores and CISA KEV data (shared templates) |
| **policy-gate** | `policy-gate` | Runs Policy Gate policy evaluation including the coverage guardrail |

## Coverage Guardrail

The pipeline assesses scan coverage across three signals (Trivy package detection,
SBOM component extraction, file type recognition) and assigns a tier:

| Tier | Severity | Pipeline Result | Meaning |
|------|----------|----------------|---------|
| **Full** | Info | Pass | All scanners had meaningful visibility |
| **Partial** | Low | Warning (exit 2) | Some scanners had limited visibility; results are a lower bound |
| **Minimal** | Medium | Fail (exit 1) | Near-zero scanner visibility; binary cannot be considered assessed |

When the pipeline fails with Minimal coverage, see
[`docs/coverage-guardrail-runbook.md`](docs/coverage-guardrail-runbook.md) for
remediation options.

## Variables Reference

Configure these in **Settings > CI/CD > Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BINARY_REF` | Yes | — | Binary to scan (URL, shorthand, or path) |
| `DEFECTDOJO_URL` | Yes | `http://defectdojo-docker-nginx-1:8080` | DefectDojo base URL |
| `DEFECTDOJO_TOKEN` | Yes | — | DefectDojo API token (should be masked) |
| `DEFECTDOJO_PRODUCT_TYPE` | No | `Research and Development` | DefectDojo product type |
| `DEPENDENCY_TRACK_URL` | Yes | `http://dtrack-apiserver:8080` | Dependency Track API base URL |
| `DT_API_TOKEN` | Yes | — | Dependency Track API key (should be masked) |
| `GITLAB_TOKEN` | No | — | GitLab PAT for private package registry downloads |
| `POLL_INTERVAL` | No | `5` | Seconds between Dependency Track polling attempts |
| `POLL_MAX_ATTEMPTS` | No | `60` | Maximum polling attempts before timeout |

## Archive Safety Limits

| Limit | Value | Reason |
|-------|-------|--------|
| Max unpacked size | 2048 MB | Prevents disk exhaustion from decompression bombs |
| Max file count | 10,000 | Prevents inode exhaustion and excessive scan time |
| Path traversal | Rejected | Prevents archive entries with `..` from escaping the unpack directory |

## Supported Archive Formats

Archives are automatically detected by MIME type and unpacked before scanning:

`.zip`, `.tar.gz`/`.tgz`, `.tar.xz`, `.msi`, `.cab`, `.deb`, `.rpm`, `.squashfs`
(AppImage/Snap)

Single binaries (non-archive) are scanned directly without unpacking.

## Integration with Existing Platform

Binary Scan uses the same shared templates (`ci/shared.yml`), DefectDojo
central findings store, Dependency Track SBOM analysis, EPSS/KEV enrichment,
and Policy Gate evaluation as [Container Scan](../container-scan) and
[Repo Scan](../repo-scan). Scan results from all three pipelines are
consolidated in DefectDojo under the same product type, enabling unified
risk management across container images, source repositories, and binary
artifacts. Shared templates are maintained in [`../templates`](../templates)
and policies in [`../policy-gate`](../policy-gate).

## Related Repositories

| Repository | Role |
|------------|------|
| [`templates`](../templates) | Shared CI/CD job templates (`.dd-reimport`, `.export-findings`, `.generate-report`, `.enrich-epss`, `.enrich-kev`, `.policy-gate`) |
| [`policy-gate`](../policy-gate) | Rego policy engine and HTML report generator |
| [`container-scan`](../container-scan) | Container image scanning pipeline |
| [`repo-scan`](../repo-scan) | Source code and dependency scanning pipeline |

[Trivy]: https://aquasecurity.github.io/trivy/
[Syft]: https://github.com/anchore/syft
[DefectDojo]: https://www.defectdojo.com/
[Dependency Track]: https://dependencytrack.org/
[Policy Gate]: https://github.com/ejacobhayes99/policy-gate
[GitLab CI/CD]: https://docs.gitlab.com/ee/ci/
