# sbom_playground
Play area for sbom testing and dependency track.

## Dependency-Track SBOM API PoC (Python)

This repo now includes a small MVP CLI: `/home/runner/work/sbom_playground/sbom_playground/dependency_track_sbom_cli.py`

### Prerequisites
- Python 3.9+
- A running Dependency-Track instance (for local testing on MacBook, commonly `http://localhost:8080`)
- A Dependency-Track API key

### Configure environment
```bash
export DEPENDENCY_TRACK_BASE_URL="http://localhost:8080"
export DEPENDENCY_TRACK_API_KEY="<your-api-key>"
```

### Upload an SBOM
```bash
python /home/runner/work/sbom_playground/sbom_playground/dependency_track_sbom_cli.py \
  upload \
  --project-uuid "<project-uuid>" \
  --sbom "/absolute/path/to/bom.json"
```

Optional project auto-creation:
```bash
python /home/runner/work/sbom_playground/sbom_playground/dependency_track_sbom_cli.py \
  upload \
  --project-uuid "<project-uuid>" \
  --sbom "/absolute/path/to/bom.json" \
  --auto-create \
  --project-name "my-app" \
  --project-version "1.0.0"
```

### Download an SBOM
CycloneDX output:
```bash
python /home/runner/work/sbom_playground/sbom_playground/dependency_track_sbom_cli.py \
  download \
  --project-uuid "<project-uuid>" \
  --format cyclonedx \
  --output "/absolute/path/to/downloaded-bom.json"
```

SPDX output:
```bash
python /home/runner/work/sbom_playground/sbom_playground/dependency_track_sbom_cli.py \
  download \
  --project-uuid "<project-uuid>" \
  --format spdx \
  --output "/absolute/path/to/downloaded-bom.spdx"
```

### Notes
- The script uses `PUT /api/v1/bom` for upload.
- The script uses `GET /api/v1/bom/{format}/project/{project_uuid}?download=true` for download.
- If download returns JSON with a `bom` field, it is automatically base64-decoded before writing to disk.
