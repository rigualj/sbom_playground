#!/usr/bin/env python3
"""Minimal Dependency-Track SBOM upload/download CLI for local testing."""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 30


def _request(
    *,
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    timeout: int,
    payload: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, str]]:
    url = f"{base_url.rstrip('/')}{path}"
    headers = {"X-Api-Key": api_key}
    body: bytes | None = None

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url=url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read()
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            return response_body, response_headers
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Dependency-Track API request failed ({error.code} {error.reason}): {detail}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach Dependency-Track API: {error.reason}") from error


def upload_sbom(args: argparse.Namespace) -> int:
    sbom_path = pathlib.Path(args.sbom)
    if not sbom_path.is_file():
        raise RuntimeError(f"SBOM file not found: {sbom_path}")

    sbom_bytes = sbom_path.read_bytes()
    payload: dict[str, Any] = {
        "project": args.project_uuid,
        "bom": base64.b64encode(sbom_bytes).decode("utf-8"),
    }

    if args.project_name:
        payload["projectName"] = args.project_name
    if args.project_version:
        payload["projectVersion"] = args.project_version
    if args.auto_create:
        payload["autoCreate"] = True

    body, _ = _request(
        base_url=args.base_url,
        api_key=args.api_key,
        method="PUT",
        path="/api/v1/bom",
        timeout=args.timeout,
        payload=payload,
    )

    if body:
        try:
            response = json.loads(body.decode("utf-8"))
            token = response.get("token")
            if token:
                print(f"Upload submitted. Processing token: {token}")
            else:
                print("Upload submitted.")
        except json.JSONDecodeError:
            print("Upload submitted.")
    else:
        print("Upload submitted.")
    return 0


def download_sbom(args: argparse.Namespace) -> int:
    query = urllib.parse.urlencode({"download": "true"})
    path = f"/api/v1/bom/{args.format}/project/{args.project_uuid}?{query}"

    body, headers = _request(
        base_url=args.base_url,
        api_key=args.api_key,
        method="GET",
        path=path,
        timeout=args.timeout,
    )

    content_type = headers.get("content-type", "")
    output_bytes = body

    if "application/json" in content_type.lower():
        try:
            payload = json.loads(body.decode("utf-8"))
            encoded_bom = payload.get("bom")
            if encoded_bom:
                output_bytes = base64.b64decode(encoded_bom)
            else:
                output_bytes = body
        except (json.JSONDecodeError, ValueError):
            output_bytes = body

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output_bytes)
    print(f"SBOM written to {output_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upload and download SBOMs using the Dependency-Track API"
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("DEPENDENCY_TRACK_BASE_URL"),
        help="Dependency-Track base URL, e.g. http://localhost:8080",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("DEPENDENCY_TRACK_API_KEY"),
        help="Dependency-Track API key (or set DEPENDENCY_TRACK_API_KEY)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    upload = subparsers.add_parser("upload", help="Upload an SBOM file")
    upload.add_argument("--project-uuid", required=True, help="Dependency-Track project UUID")
    upload.add_argument("--sbom", required=True, help="Path to the SBOM file to upload")
    upload.add_argument("--project-name", help="Project name (used with --auto-create)")
    upload.add_argument("--project-version", help="Project version (used with --auto-create)")
    upload.add_argument(
        "--auto-create",
        action="store_true",
        help="Auto-create project when used with --project-name and --project-version",
    )
    upload.set_defaults(func=upload_sbom)

    download = subparsers.add_parser("download", help="Download a project SBOM")
    download.add_argument("--project-uuid", required=True, help="Dependency-Track project UUID")
    download.add_argument(
        "--format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM output format",
    )
    download.add_argument("--output", required=True, help="Path to write the downloaded SBOM")
    download.set_defaults(func=download_sbom)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.base_url:
        parser.error("--base-url is required (or set DEPENDENCY_TRACK_BASE_URL)")
    if not args.api_key:
        parser.error("--api-key is required (or set DEPENDENCY_TRACK_API_KEY)")

    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
