#!/bin/sh
set -euo pipefail

# ──────────────────────────────────────────────
# parse-binary-ref.sh
#
# Parse BINARY_REF, download/copy the target,
# unpack archives, and write scan.env dotenv.
# ──────────────────────────────────────────────

apk add --no-cache file unzip tar coreutils msitools cabextract rpm2cpio dpkg squashfs-tools

WORKSPACE="${CI_PROJECT_DIR}/scan-workspace"
DOWNLOAD_PATH="${WORKSPACE}/artifact.download"
UNPACK_DIR="${WORKSPACE}/unpacked"
MAX_UNPACKED_MB=2048
MAX_FILE_COUNT=10000

mkdir -p "${WORKSPACE}" "${UNPACK_DIR}"

# ── Validate input ────────────────────────────
if [ -z "${BINARY_REF:-}" ]; then
  printf '[binary-scan:init] ERROR: BINARY_REF is not set.\n'
  printf 'Usage:\n'
  printf '  BINARY_REF=https://example.com/path/to/artifact.tar.gz\n'
  printf '  BINARY_REF=project-id:package-name:version:filename\n'
  printf '  BINARY_REF=/path/to/local/file\n'
  exit 1
fi

printf '[binary-scan:init] BINARY_REF=%s\n' "${BINARY_REF}"

# ── Download / copy ───────────────────────────
if printf '%s' "${BINARY_REF}" | grep -qE '^https://'; then
  # HTTPS URL
  printf '[binary-scan:init] Downloading from URL...\n'
  WGET_ARGS=""
  if printf '%s' "${BINARY_REF}" | grep -q '/packages/generic/' && [ -n "${GITLAB_TOKEN:-}" ]; then
    WGET_ARGS="--header=PRIVATE-TOKEN: ${GITLAB_TOKEN}"
  fi
  if ! wget -T 300 ${WGET_ARGS} -O "${DOWNLOAD_PATH}" "${BINARY_REF}"; then
    printf '[binary-scan:init] ERROR: Failed to download %s\n' "${BINARY_REF}"
    exit 1
  fi

elif printf '%s' "${BINARY_REF}" | grep -qE '^[0-9]+:[^:]+:[^:]+:[^:]+$'; then
  # GitLab generic package shorthand: project-id:package:version:filename
  PROJECT_ID=$(printf '%s' "${BINARY_REF}" | cut -d: -f1)
  PACKAGE=$(printf '%s' "${BINARY_REF}" | cut -d: -f2)
  VERSION=$(printf '%s' "${BINARY_REF}" | cut -d: -f3)
  FILENAME=$(printf '%s' "${BINARY_REF}" | cut -d: -f4)

  # Validate shorthand fields: alphanumerics, hyphens, dots, underscores only
  for field_name in PACKAGE VERSION FILENAME; do
    eval field_val="\${${field_name}}"
    if printf '%s' "${field_val}" | grep -qE '[^a-zA-Z0-9._-]'; then
      printf '[binary-scan:init] ERROR: %s contains invalid characters: %s\n' "${field_name}" "${field_val}"
      printf 'Allowed: alphanumerics, hyphens, dots, underscores\n'
      exit 1
    fi
  done

  DOWNLOAD_URL="${CI_SERVER_URL}/api/v4/projects/${PROJECT_ID}/packages/generic/${PACKAGE}/${VERSION}/${FILENAME}"
  printf '[binary-scan:init] Downloading from GitLab package registry: %s\n' "${DOWNLOAD_URL}"
  if ! wget -T 300 --header="PRIVATE-TOKEN: ${CI_JOB_TOKEN}" -O "${DOWNLOAD_PATH}" "${DOWNLOAD_URL}"; then
    printf '[binary-scan:init] ERROR: Failed to download package %s\n' "${BINARY_REF}"
    exit 1
  fi

elif printf '%s' "${BINARY_REF}" | grep -qE '^/'; then
  # Filesystem path
  if [ ! -f "${BINARY_REF}" ]; then
    printf '[binary-scan:init] ERROR: File not found: %s\n' "${BINARY_REF}"
    exit 1
  fi
  printf '[binary-scan:init] Copying from filesystem: %s\n' "${BINARY_REF}"
  cp "${BINARY_REF}" "${DOWNLOAD_PATH}"

else
  printf '[binary-scan:init] ERROR: Unrecognized BINARY_REF format: %s\n' "${BINARY_REF}"
  printf 'Supported formats:\n'
  printf '  HTTPS URL:                https://example.com/path/to/artifact.tar.gz\n'
  printf '  GitLab package shorthand: project-id:package-name:version:filename\n'
  printf '  Filesystem path:          /path/to/local/file\n'
  exit 1
fi

DOWNLOAD_SIZE=$(wc -c < "${DOWNLOAD_PATH}")
printf '[binary-scan:init] Downloaded %s bytes\n' "${DOWNLOAD_SIZE}"

MAX_DOWNLOAD_MB=1024
DOWNLOAD_MB=$((DOWNLOAD_SIZE / 1048576))
if [ "${DOWNLOAD_MB}" -gt "${MAX_DOWNLOAD_MB}" ]; then
  printf '[binary-scan:init] ERROR: Download size %s MB exceeds limit of %s MB\n' "${DOWNLOAD_MB}" "${MAX_DOWNLOAD_MB}"
  exit 1
fi

# ── Archive handling ──────────────────────────
MIME_TYPE=$(file --mime-type -b "${DOWNLOAD_PATH}")
printf '[binary-scan:init] Detected MIME type: %s\n' "${MIME_TYPE}"

case "${MIME_TYPE}" in
  application/zip)
    if unzip -l "${DOWNLOAD_PATH}" | awk 'NR>3{print $4}' | grep -qE '(^|/)\.\./|^/'; then
      printf '[binary-scan:init] ERROR: Archive contains path traversal or absolute paths\n'
      exit 1
    fi
    unzip -o "${DOWNLOAD_PATH}" -d "${UNPACK_DIR}"
    ;;
  application/gzip|application/x-tar)
    if tar -tf "${DOWNLOAD_PATH}" | grep -qE '(^|/)\.\./|^\./\.\./|^/'; then
      printf '[binary-scan:init] ERROR: Archive contains path traversal or absolute paths\n'
      exit 1
    fi
    tar xzf "${DOWNLOAD_PATH}" -C "${UNPACK_DIR}"
    ;;
  application/x-xz)
    if tar -tf "${DOWNLOAD_PATH}" | grep -qE '(^|/)\.\./|^\./\.\./|^/'; then
      printf '[binary-scan:init] ERROR: Archive contains path traversal or absolute paths\n'
      exit 1
    fi
    tar xJf "${DOWNLOAD_PATH}" -C "${UNPACK_DIR}"
    ;;
  application/x-msi|application/x-ole-storage|application/vnd.ms-msi)
    printf '[binary-scan:init] Extracting MSI with msiextract...\n'
    msiextract -C "${UNPACK_DIR}" "${DOWNLOAD_PATH}" || {
      printf '[binary-scan:init] WARN: msiextract failed, keeping raw MSI\n'
      mv "${DOWNLOAD_PATH}" "${UNPACK_DIR}/"
    }
    ;;
  application/vnd.ms-cab-compressed)
    printf '[binary-scan:init] Extracting CAB with cabextract...\n'
    cabextract -d "${UNPACK_DIR}" "${DOWNLOAD_PATH}" || {
      printf '[binary-scan:init] WARN: cabextract failed, keeping raw CAB\n'
      mv "${DOWNLOAD_PATH}" "${UNPACK_DIR}/"
    }
    ;;
  application/vnd.debian.binary-package|application/x-archive)
    printf '[binary-scan:init] Extracting DEB with dpkg-deb...\n'
    dpkg-deb -x "${DOWNLOAD_PATH}" "${UNPACK_DIR}" || {
      printf '[binary-scan:init] WARN: dpkg-deb failed, keeping raw file\n'
      mv "${DOWNLOAD_PATH}" "${UNPACK_DIR}/"
    }
    ;;
  application/x-rpm)
    printf '[binary-scan:init] Extracting RPM with rpm2cpio...\n'
    (cd "${UNPACK_DIR}" && rpm2cpio "${DOWNLOAD_PATH}" | cpio -idm) || {
      printf '[binary-scan:init] WARN: rpm2cpio failed, keeping raw RPM\n'
      mv "${DOWNLOAD_PATH}" "${UNPACK_DIR}/"
    }
    ;;
  application/x-squashfs)
    printf '[binary-scan:init] Extracting SquashFS (AppImage/Snap)...\n'
    unsquashfs -d "${UNPACK_DIR}/squashfs-root" "${DOWNLOAD_PATH}" || {
      printf '[binary-scan:init] WARN: unsquashfs failed, keeping raw file\n'
      mv "${DOWNLOAD_PATH}" "${UNPACK_DIR}/"
    }
    ;;
  *)
    # Single binary — move into unpacked directory
    mv "${DOWNLOAD_PATH}" "${UNPACK_DIR}/"
    ;;
esac

# ── Safety checks on unpacked content ─────────
UNPACKED_SIZE=$(du -sm "${UNPACK_DIR}" | awk '{print $1}')
if [ "${UNPACKED_SIZE}" -gt "${MAX_UNPACKED_MB}" ]; then
  printf '[binary-scan:init] ERROR: Unpacked size %s MB exceeds limit of %s MB\n' "${UNPACKED_SIZE}" "${MAX_UNPACKED_MB}"
  exit 1
fi

FILE_COUNT=$(find "${UNPACK_DIR}" -type f | wc -l)
if [ "${FILE_COUNT}" -gt "${MAX_FILE_COUNT}" ]; then
  printf '[binary-scan:init] ERROR: File count %s exceeds limit of %s\n' "${FILE_COUNT}" "${MAX_FILE_COUNT}"
  exit 1
fi

printf '[binary-scan:init] Unpacked: %s MB, %s files\n' "${UNPACKED_SIZE}" "${FILE_COUNT}"

# ── Derive product name and tag ───────────────
# Extract filename from BINARY_REF
case "${BINARY_REF}" in
  https://*)
    RAW_FILENAME=$(printf '%s' "${BINARY_REF}" | sed 's|.*/||' | sed 's|?.*||')
    ;;
  /*)
    RAW_FILENAME=$(basename "${BINARY_REF}")
    ;;
  *)
    # Shorthand: use the filename field (4th colon-delimited)
    RAW_FILENAME=$(printf '%s' "${BINARY_REF}" | cut -d: -f4)
    ;;
esac

printf '[binary-scan:init] Raw filename: %s\n' "${RAW_FILENAME}"

# Strip compound archive extensions first, then single extensions
STRIPPED="${RAW_FILENAME}"
STRIPPED=$(printf '%s' "${STRIPPED}" | sed 's/\.tar\.gz$//')
STRIPPED=$(printf '%s' "${STRIPPED}" | sed 's/\.tar\.xz$//')
STRIPPED=$(printf '%s' "${STRIPPED}" | sed 's/\.tar\.bz2$//')
STRIPPED=$(printf '%s' "${STRIPPED}" | sed -E 's/\.(zip|gz|xz|bz2|jar|war|ear|bin|exe|elf|so|dll|deb|rpm|apk|msi|cab|dmg|pkg|snap|appimage)$//I')

# Extract version — try URL path first (covers GitHub/GitLab releases
# and most CDN layouts), then fall back to filename
VERSION_PATTERN='v?[0-9]+\.[0-9]+(\.[0-9]+)?'
SCAN_TAG=""

# For URLs, scan the path (excluding the filename) for a version segment
if printf '%s' "${BINARY_REF}" | grep -qE '^https://'; then
  # Strip query string, then filename, leaving the directory path
  URL_PATH=$(printf '%s' "${BINARY_REF}" | sed 's|?.*||' | sed 's|/[^/]*$||')
  # GitHub/GitLab releases: .../releases/download/v1.2.3/filename
  # Generic: any path segment that is purely a version (e.g., /v4.44.6/)
  SCAN_TAG=$(printf '%s' "${URL_PATH}" | grep -oE '(^|/)v?[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's|^/||' | tail -1 || true)
  if [ -n "${SCAN_TAG}" ]; then
    printf '[binary-scan:init] Version extracted from URL path: %s\n' "${SCAN_TAG}"
  fi
fi

# Fall back to extracting version from the filename
if [ -z "${SCAN_TAG}" ]; then
  SCAN_TAG=$(printf '%s' "${STRIPPED}" | grep -oE "${VERSION_PATTERN}" | head -1 || true)
fi

# Derive product name: strip from the first version match onward,
# then strip trailing separators and platform suffixes
# Escape SCAN_TAG for use in sed (dots, etc. are regex metacharacters)
SCAN_TAG_ESC=$(printf '%s' "${SCAN_TAG}" | sed 's/[.[\*^$/]/\\&/g')

if [ -n "${SCAN_TAG}" ]; then
  SCAN_PRODUCT_NAME=$(printf '%s' "${STRIPPED}" | sed "s/[-_.]${SCAN_TAG_ESC}.*//")
  # Also try without separator if the above didn't strip anything
  if [ "${SCAN_PRODUCT_NAME}" = "${STRIPPED}" ]; then
    SCAN_PRODUCT_NAME=$(printf '%s' "${STRIPPED}" | sed "s/${SCAN_TAG_ESC}.*//")
  fi
else
  # No version found — use SHA-256 of the file as the tag
  SCAN_TAG=$(sha256sum "${DOWNLOAD_PATH}" 2>/dev/null | cut -c1-12 || sha256sum "${UNPACK_DIR}/$(ls "${UNPACK_DIR}" | head -1)" | cut -c1-12)
  SCAN_PRODUCT_NAME="${STRIPPED}"
fi

# Clean trailing separators from product name
SCAN_PRODUCT_NAME=$(printf '%s' "${SCAN_PRODUCT_NAME}" | sed 's/[-_.]*$//')

# Strip platform/arch suffixes (e.g., -linux-amd64, -darwin-arm64)
SCAN_PRODUCT_NAME=$(printf '%s' "${SCAN_PRODUCT_NAME}" | sed -E 's/[-_](linux|darwin|windows|amd64|arm64|x86_64|i386|x86).*//I')

if [ -z "${SCAN_PRODUCT_NAME}" ]; then
  # GitHub/GitLab archive URLs encode the project in the path, not the filename
  # GitHub:  https://github.com/{owner}/{repo}/archive/...
  # GitLab:  https://{host}/{group...}/{project}/-/archive/...
  if printf '%s' "${BINARY_REF}" | grep -qE '^https://github\.com/[^/]+/[^/]+/archive/'; then
    SCAN_PRODUCT_NAME=$(printf '%s' "${BINARY_REF}" | sed -E 's|^https://github\.com/[^/]+/([^/]+)/archive/.*|\1|')
  elif printf '%s' "${BINARY_REF}" | grep -qE '^https://.*/-/archive/'; then
    SCAN_PRODUCT_NAME=$(printf '%s' "${BINARY_REF}" | sed -E 's|^https://.*/([^/]+)/-/archive/.*|\1|')
  else
    SCAN_PRODUCT_NAME="${RAW_FILENAME}"
  fi
fi

printf '[binary-scan:init] Product: %s, Tag: %s\n' "${SCAN_PRODUCT_NAME}" "${SCAN_TAG}"

# ── Sanitize and write dotenv ─────────────────
# Strip characters unsafe for unquoted dotenv values
SCAN_PRODUCT_NAME=$(printf '%s' "${SCAN_PRODUCT_NAME}" | tr -cd 'a-zA-Z0-9._-')
SCAN_TAG=$(printf '%s' "${SCAN_TAG}" | tr -cd 'a-zA-Z0-9._-')

if [ -z "${SCAN_PRODUCT_NAME}" ]; then
  SCAN_PRODUCT_NAME="unknown"
fi
if [ -z "${SCAN_TAG}" ]; then
  SCAN_TAG="unknown"
fi

{
  printf 'SCAN_PRODUCT_NAME=%s\n' "${SCAN_PRODUCT_NAME}"
  printf 'SCAN_TAG=%s\n' "${SCAN_TAG}"
  printf 'SCAN_ENGAGEMENT_PREFIX=Binary Scan Pipeline\n'
  printf 'SCAN_TARGET_DIR=%s\n' "${CI_PROJECT_DIR}/scan-workspace/unpacked"
} > "${CI_PROJECT_DIR}/scan.env"

printf '[binary-scan:init] scan.env written:\n'
cat "${CI_PROJECT_DIR}/scan.env"
