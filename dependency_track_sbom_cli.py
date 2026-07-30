#!/usr/bin/env python3
"""Minimal Dependency-Track SBOM upload/download CLI for local testing."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_ENV_PATH = ".env"


def _load_dotenv(env_path: str = DEFAULT_ENV_PATH) -> None:
    """Load key-value pairs from a .env file into process environment."""
    path = pathlib.Path(env_path)
    if not path.is_file():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]

        os.environ[key] = value


def _prompt_text(label: str, *, secret: bool = False, default: str | None = None) -> str:
    prompt = f"{label}"
    if default:
        prompt += f" [{default}]"
    prompt += ": "

    while True:
        if secret:
            value = getpass.getpass(prompt)
        else:
            value = input(prompt)

        value = value.strip()
        if value:
            return value
        if default is not None:
            return default
        print(f"{label} is required.")


def _prompt_yes_no(question: str, *, default: bool = True) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        answer = input(f"{question}{suffix}").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _interactive_missing_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    is_tty = sys.stdin.isatty()

    if not args.base_url:
        if is_tty:
            args.base_url = _prompt_text("Dependency-Track base URL")
        else:
            parser.error("--base-url is required (or set DEPENDENCY_TRACK_BASE_URL in shell/.env)")

    if not args.api_key:
        if is_tty:
            args.api_key = _prompt_text("Dependency-Track API key", secret=True)
        else:
            parser.error("--api-key is required (or set DEPENDENCY_TRACK_API_KEY in shell/.env)")

    if args.command == "upload":
        if not args.sbom:
            if is_tty:
                args.sbom = _prompt_text("Path to SBOM file")
            else:
                parser.error("upload requires --sbom")

        if not args.project_uuid:
            if is_tty:
                args.project_name = args.project_name or _prompt_text("Project name")
                args.project_version = args.project_version or _prompt_text("Project version")
                if not args.auto_create:
                    args.auto_create = _prompt_yes_no(
                        "No project UUID provided. Auto-create project using name/version?",
                        default=True,
                    )
            elif not (args.project_name and args.project_version and args.auto_create):
                parser.error(
                    "upload without --project-uuid requires --project-name, --project-version, and --auto-create"
                )

        if not args.project_uuid and not args.auto_create:
            parser.error("upload without --project-uuid requires --auto-create")

        if args.auto_create and (not args.project_name or not args.project_version):
            parser.error("--auto-create requires --project-name and --project-version")

    if args.command == "download":
        if not args.project_uuid:
            if is_tty:
                args.project_uuid = _prompt_text("Dependency-Track project UUID")
            else:
                parser.error("download requires --project-uuid")
        if not args.output:
            if is_tty:
                args.output = _prompt_text("Path to write downloaded SBOM")
            else:
                parser.error("download requires --output")

    if args.command == "set-tags":
        if not args.project_uuid:
            if is_tty:
                args.project_uuid = _prompt_text("Dependency-Track project UUID")
            else:
                parser.error("set-tags requires --project-uuid")
        if not args.project_tags:
            if is_tty:
                args.project_tags = _prompt_text("Comma-separated project tags")
            else:
                parser.error("set-tags requires --project-tags")

    if args.command == "list-sboms":
        if not args.project_name:
            if is_tty:
                args.project_name = _prompt_text("Project name")
            else:
                parser.error("list-sboms requires --project-name")


def _parse_project_tags(raw_tags: str | None) -> list[str]:
    if not raw_tags:
        return []

    tags = [tag.strip() for tag in raw_tags.split(",")]
    return [tag for tag in tags if tag]


def _tag_objects(tag_names: list[str]) -> list[dict[str, str]]:
    return [{"name": tag_name} for tag_name in tag_names]


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
    payload: dict[str, Any] = {"bom": base64.b64encode(sbom_bytes).decode("utf-8")}

    if args.project_uuid:
        payload["project"] = args.project_uuid

    if args.project_name:
        payload["projectName"] = args.project_name
    if args.project_version:
        payload["projectVersion"] = args.project_version
    if args.auto_create:
        payload["autoCreate"] = True
    project_tags = _parse_project_tags(args.project_tags)
    if project_tags:
        payload["projectTags"] = project_tags

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


def check_api(args: argparse.Namespace) -> int:
    body, _ = _request(
        base_url=args.base_url,
        api_key=args.api_key,
        method="GET",
        path="/api/version",
        timeout=args.timeout,
    )

    if not body:
        print("Dependency-Track API reachable. Empty response body.")
        return 0

    try:
        payload = json.loads(body.decode("utf-8"))
        print(json.dumps(payload, indent=2))
    except json.JSONDecodeError:
        print(body.decode("utf-8", errors="replace"))

    return 0


def list_projects(args: argparse.Namespace) -> int:
    query = urllib.parse.urlencode(
        {
            "pageNumber": str(args.page_number),
            "pageSize": str(args.page_size),
        }
    )
    path = f"/api/v1/project?{query}"

    body, _ = _request(
        base_url=args.base_url,
        api_key=args.api_key,
        method="GET",
        path=path,
        timeout=args.timeout,
    )

    if not body:
        print("No projects returned.")
        return 0

    try:
        payload = json.loads(body.decode("utf-8"))
        print(json.dumps(payload, indent=2))
    except json.JSONDecodeError:
        print(body.decode("utf-8", errors="replace"))

    return 0


def list_sboms(args: argparse.Namespace) -> int:
    target_name = args.project_name.strip().lower()
    page_number = 1
    page_size = 100
    matches: list[dict[str, Any]] = []

    while True:
        query = urllib.parse.urlencode(
            {
                "pageNumber": str(page_number),
                "pageSize": str(page_size),
            }
        )
        path = f"/api/v1/project?{query}"

        body, _ = _request(
            base_url=args.base_url,
            api_key=args.api_key,
            method="GET",
            path=path,
            timeout=args.timeout,
        )

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise RuntimeError("Could not parse project listing response") from error

        if not isinstance(payload, list):
            raise RuntimeError("Unexpected project listing format")
        if not payload:
            break

        for project in payload:
            if not isinstance(project, dict):
                continue
            name = str(project.get("name", "")).strip().lower()
            if name == target_name:
                matches.append(project)

        if len(payload) < page_size:
            break
        page_number += 1

    if not matches:
        print(f"No project versions found for name: {args.project_name}")
        return 0

    print(f"Found {len(matches)} project version(s) for {args.project_name}:")
    for project in matches:
        project_uuid = project.get("uuid", "")
        project_name = project.get("name", "")
        project_version = project.get("version", "")
        last_bom_import = project.get("lastBomImport")
        last_bom_import_format = project.get("lastBomImportFormat")
        has_bom = bool(last_bom_import)

        print("-" * 80)
        print(f"UUID: {project_uuid}")
        print(f"Name: {project_name}")
        print(f"Version: {project_version}")
        print(f"Has BOM: {'yes' if has_bom else 'no'}")
        print(f"Last BOM import: {last_bom_import or 'n/a'}")
        print(f"Last BOM import format: {last_bom_import_format or 'n/a'}")
        print("Download formats: cyclonedx, spdx")

        if args.include_download_commands and project_uuid:
            print("Download commands:")
            print(
                "  python3 dependency_track_sbom_cli.py download "
                f"--project-uuid \"{project_uuid}\" --format cyclonedx "
                f"--output \"downloads/{project_name}-{project_version}.cdx.json\""
            )
            print(
                "  python3 dependency_track_sbom_cli.py download "
                f"--project-uuid \"{project_uuid}\" --format spdx "
                f"--output \"downloads/{project_name}-{project_version}.spdx\""
            )

    return 0


def set_project_tags(args: argparse.Namespace) -> int:
    project_uuid = args.project_uuid
    project_tags = _parse_project_tags(args.project_tags)
    if not project_tags:
        raise RuntimeError("No valid tags were provided")

    body, _ = _request(
        base_url=args.base_url,
        api_key=args.api_key,
        method="GET",
        path=f"/api/v1/project/{project_uuid}",
        timeout=args.timeout,
    )

    try:
        project_payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError("Could not parse project response while setting tags") from error

    if not isinstance(project_payload, dict):
        raise RuntimeError("Unexpected project response format while setting tags")

    update_payload: dict[str, Any] = {
        "uuid": project_payload.get("uuid"),
        "name": project_payload.get("name"),
        "version": project_payload.get("version"),
        "classifier": project_payload.get("classifier"),
        "active": project_payload.get("active", True),
        "tags": _tag_objects(project_tags),
    }

    if not update_payload["uuid"]:
        raise RuntimeError("Project response did not include a uuid")
    if not update_payload["name"]:
        raise RuntimeError("Project response did not include a name")
    if not update_payload["version"]:
        raise RuntimeError("Project response did not include a version")
    if not update_payload["classifier"]:
        raise RuntimeError("Project response did not include a classifier")

    _request(
        base_url=args.base_url,
        api_key=args.api_key,
        method="POST",
        path="/api/v1/project",
        timeout=args.timeout,
        payload=update_payload,
    )

    print(f"Updated project tags for {project_uuid}: {', '.join(project_tags)}")
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
    parser.add_argument(
        "--check_api",
        "--check-api",
        dest="check_api",
        action="store_true",
        help="Verify API reachability/authentication using GET /api/version",
    )
    parser.add_argument(
        "--list_projects",
        "--list-projects",
        dest="list_projects",
        action="store_true",
        help="List Dependency-Track projects using GET /api/v1/project",
    )
    parser.add_argument(
        "--page-number",
        type=int,
        default=1,
        help="Page number for --list_projects (default: 1)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=10,
        help="Page size for --list_projects (default: 10)",
    )

    subparsers = parser.add_subparsers(dest="command")

    upload = subparsers.add_parser("upload", help="Upload an SBOM file")
    upload.add_argument(
        "--project-uuid",
        help="Dependency-Track project UUID (optional when using --auto-create with name/version)",
    )
    upload.add_argument("--sbom", help="Path to the SBOM file to upload")
    upload.add_argument("--project-name", help="Project name (used with --auto-create)")
    upload.add_argument("--project-version", help="Project version (used with --auto-create)")
    upload.add_argument(
        "--project-tags",
        help="Optional comma-separated tags to associate with the project",
    )
    upload.add_argument(
        "--auto-create",
        action="store_true",
        help="Auto-create project when used with --project-name and --project-version",
    )
    upload.set_defaults(func=upload_sbom)

    download = subparsers.add_parser("download", help="Download a project SBOM")
    download.add_argument("--project-uuid", help="Dependency-Track project UUID")
    download.add_argument(
        "--format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM output format",
    )
    download.add_argument("--output", help="Path to write the downloaded SBOM")
    download.set_defaults(func=download_sbom)

    set_tags = subparsers.add_parser("set-tags", help="Set tags on an existing project")
    set_tags.add_argument("--project-uuid", help="Dependency-Track project UUID")
    set_tags.add_argument("--project-tags", help="Comma-separated project tags")
    set_tags.set_defaults(func=set_project_tags)

    list_sboms_cmd = subparsers.add_parser(
        "list-sboms",
        help="List available SBOMs for all versions of a project name",
    )
    list_sboms_cmd.add_argument("--project-name", help="Project name to search (exact match)")
    list_sboms_cmd.add_argument(
        "--include-download-commands",
        action="store_true",
        help="Print ready-to-run download commands for each matching project version",
    )
    list_sboms_cmd.set_defaults(func=list_sboms)

    return parser


def main() -> int:
    _load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    if args.command and (args.check_api or args.list_projects):
        parser.error("Use either a subcommand or one of --check_api/--list_projects, not both")
    if not args.command and not args.check_api and not args.list_projects:
        parser.error("Specify a subcommand or one of --check_api/--list_projects")
    if args.page_number < 1:
        parser.error("--page-number must be >= 1")
    if args.page_size < 1:
        parser.error("--page-size must be >= 1")

    _interactive_missing_args(parser, args)

    if args.check_api:
        return check_api(args)
    if args.list_projects:
        return list_projects(args)

    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
