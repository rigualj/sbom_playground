# sbom_playground
Play area for sbom testing and dependency track.

## Dependency-Track SBOM API PoC (Python)

This repo now includes a small MVP CLI: `dependency_track_sbom_cli.py`

### Prerequisites
- Python 3.9+
- A running Dependency-Track instance (for local testing on MacBook, commonly `http://localhost:8080`)
- A Dependency-Track API key

### Configure environment
The CLI now reads values from either shell environment variables or a local `.env` file.

1) Copy the example file:
```bash
cp .env.example .env
```

2) Edit `.env`:
```bash
DEPENDENCY_TRACK_BASE_URL="http://localhost:8080"
DEPENDENCY_TRACK_API_KEY="<your-api-key>"
```

You can still use shell exports if you prefer:
```bash
export DEPENDENCY_TRACK_BASE_URL="http://localhost:8080"
export DEPENDENCY_TRACK_API_KEY="<your-api-key>"
```

### Quick Start Verification
Load variables from `.env` in your current shell:
```bash
set -a
source .env
set +a
```

Check network reachability and API key authentication:
```bash
python3 dependency_track_sbom_cli.py --check_api
```

List projects (first page) to verify authenticated API access:
```bash
python3 dependency_track_sbom_cli.py --list_projects
```

List a custom page and page size:
```bash
python3 dependency_track_sbom_cli.py --list_projects --page-number 2 --page-size 25
```

### Upload an SBOM
```bash
python3 dependency_track_sbom_cli.py \
  upload \
  --sbom "/absolute/path/to/bom.json"
```

Project selection options:
- Existing project by UUID:
```bash
python3 dependency_track_sbom_cli.py \
  upload \
  --project-uuid "<project-uuid>" \
  --sbom "/absolute/path/to/bom.json"
```

- Auto-create project if it does not exist (name + version):
```bash
python3 dependency_track_sbom_cli.py \
  upload \
  --sbom "/absolute/path/to/bom.json" \
  --auto-create \
  --project-name "my-app" \
  --project-version "1.0.0"
```

- Optional tags on upload (works with existing or auto-created projects):
```bash
python3 dependency_track_sbom_cli.py \
  upload \
  --sbom "/absolute/path/to/bom.json" \
  --project-uuid "<project-uuid>" \
  --project-tags "prod,customer-facing,critical"
```

Set tags on an existing project (standalone):
```bash
python3 dependency_track_sbom_cli.py \
  set-tags \
  --project-uuid "<project-uuid>" \
  --project-tags "prod,customer-facing,critical"
```

If required arguments are not passed, the script prompts for them interactively (for example, project UUID, project name/version, or output path).

### Download an SBOM
CycloneDX output:
```bash
python3 dependency_track_sbom_cli.py \
  download \
  --project-uuid "<project-uuid>" \
  --format cyclonedx \
  --output "/absolute/path/to/downloaded-bom.json"
```

SPDX output:
```bash
python3 dependency_track_sbom_cli.py \
  download \
  --project-uuid "<project-uuid>" \
  --format spdx \
  --output "/absolute/path/to/downloaded-bom.spdx"
```

### Notes
- The script uses `PUT /api/v1/bom` for upload.
- The script uses `GET /api/v1/bom/{format}/project/{project_uuid}?download=true` for download.
- If download returns JSON with a `bom` field, it is automatically base64-decoded before writing to disk.
