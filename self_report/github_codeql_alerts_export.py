#!/usr/bin/env python3

"""
Export CodeQL C/C++ code scanning alerts from GitHub Enterprise Cloud
to CSV.

Features:
- Organization-wide or single-repository export
- CodeQL-only filtering
- C/C++ filtering using cpp/* CodeQL rule IDs
- Handles pagination
- Retries transient HTTP failures
- Handles GitHub API rate limiting
- Uses token from environment variable
- Does not print the token
- UTF-8 CSV output
- Includes triage/dismissal information
- Includes alert assignee/owner information
- Includes file and line information
- Includes commit SHA
- Atomic CSV output
- Useful logging
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_API_VERSION = "2026-03-10"
DEFAULT_PER_PAGE = 100
DEFAULT_TIMEOUT = 60

CSV_COLUMNS = [
    "Repository",
    "Alert ID",
    "Rule ID",
    "Rule Name",
    "Rule Description",
    "Severity",
    "Security Severity",
    "File",
    "Start Line",
    "End Line",
    "State",
    "Assignee / Owner",
    "Dismissed By",
    "Dismissed At",
    "Dismissal Reason",
    "Triage Comment",
    "Commit SHA",
    "Branch / Ref",
    "Alert URL",
]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("github-codeql-export")


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def create_session(token: str) -> requests.Session:
    session = requests.Session()

    retry = Retry(
        total=5,
        connect=5,
        read=5,
        status=5,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=10,
    )

    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": DEFAULT_API_VERSION,
            "User-Agent": "CodeQL-Alert-CSV-Exporter/1.0",
        }
    )

    return session


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def get_json(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    GET JSON with explicit handling for authentication, rate limiting,
    permission, and API errors.
    """

    logger.debug("GET %s params=%s", url, params)

    try:
        response = session.get(
            url,
            params=params,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"GitHub API request failed: {exc}") from exc

    # Rate limit diagnostics
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset = response.headers.get("X-RateLimit-Reset")

    logger.debug(
        "HTTP %s | rate_remaining=%s | rate_reset=%s",
        response.status_code,
        remaining,
        reset,
    )

    if response.status_code == 401:
        raise RuntimeError(
            "GitHub authentication failed (HTTP 401). "
            "Check GITHUB_TOKEN."
        )

    if response.status_code == 403:
        message = safe_error_message(response)

        if remaining == "0":
            raise RuntimeError(
                "GitHub API rate limit exhausted. "
                f"Rate-limit reset epoch: {reset}. "
                f"API message: {message}"
            )

        raise RuntimeError(
            "GitHub API returned HTTP 403. "
            f"Check token permissions and repository access. "
            f"API message: {message}"
        )

    if response.status_code == 404:
        raise RuntimeError(
            "GitHub resource not found (HTTP 404). "
            "Check organization/repository name and token access."
        )

    if response.status_code >= 400:
        raise RuntimeError(
            f"GitHub API returned HTTP {response.status_code}: "
            f"{safe_error_message(response)}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"GitHub API returned invalid JSON. HTTP {response.status_code}"
        ) from exc


def safe_error_message(response: requests.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(data.get("message", data))
        return str(data)
    except ValueError:
        return response.text[:500]


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def paginate(
    session: requests.Session,
    url: str,
    params: Dict[str, Any],
) -> Iterable[Dict[str, Any]]:
    """
    Paginate GitHub REST API using page/per_page.
    """

    page = 1

    while True:
        request_params = dict(params)
        request_params["page"] = page
        request_params["per_page"] = DEFAULT_PER_PAGE

        logger.info("Fetching page %d...", page)

        data = get_json(
            session,
            url,
            request_params,
        )

        if not isinstance(data, list):
            raise RuntimeError(
                f"Expected list response from {url}, "
                f"received {type(data).__name__}"
            )

        if not data:
            break

        for item in data:
            yield item

        if len(data) < DEFAULT_PER_PAGE:
            break

        page += 1


# ---------------------------------------------------------------------------
# Alert processing
# ---------------------------------------------------------------------------

def is_cpp_codeql_alert(alert: Dict[str, Any]) -> bool:
    """
    CodeQL C/C++ query IDs normally use the cpp/ namespace.

    Examples:
        cpp/sql-injection
        cpp/command-line-injection
        cpp/uncontrolled-allocation-size
    """

    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id") or "").lower()

# for now, supporting multiple language alerts
#    LANGUAGE_PREFIXES = (
#    "cpp/",
#    "c/",
#    "java/",
#    "javascript/",
#    "python/",
#    "go/"
#)
#    return rule_id.startswith(LANGUAGE_PREFIXES)

# for now, only C/C++ alerts
    #return rule_id.startswith("cpp/")

    #all language alerts
    return rule_id.startswith("")


def get_assignees(alert: Dict[str, Any]) -> str:
    """
    GitHub API responses can contain an assignees list.

    Handle multiple assignees and different response shapes defensively.
    """

    assignees = alert.get("assignees") or []

    if not isinstance(assignees, list):
        return "N/A"

    names: List[str] = []

    for assignee in assignees:
        if isinstance(assignee, str):
            names.append(assignee)
        elif isinstance(assignee, dict):
            login = assignee.get("login")
            if login:
                names.append(str(login))

    if not names:
        return "Unassigned"

    return ", ".join(sorted(set(names)))


def get_dismissed_by(alert: Dict[str, Any]) -> str:
    dismissed_by = alert.get("dismissed_by")

    if isinstance(dismissed_by, dict):
        return str(dismissed_by.get("login") or "N/A")

    if isinstance(dismissed_by, str):
        return dismissed_by

    return "N/A"


def get_repository(alert: Dict[str, Any]) -> str:
    repository = alert.get("repository") or {}

    if isinstance(repository, dict):
        full_name = repository.get("full_name")
        if full_name:
            return str(full_name)

        name = repository.get("name")
        owner = repository.get("owner") or {}

        if name and isinstance(owner, dict):
            owner_login = owner.get("login")
            if owner_login:
                return f"{owner_login}/{name}"

    # Repository endpoint does not necessarily return repository object.
    # Fall back to URL parsing if possible.
    html_url = str(alert.get("html_url") or "")

    parts = html_url.split("/")

    try:
        repo_index = parts.index("code-scanning")
        if repo_index >= 2:
            return f"{parts[3]}/{parts[4]}"
    except (ValueError, IndexError):
        pass

    return "N/A"


def alert_to_row(alert: Dict[str, Any]) -> Dict[str, str]:
    rule = alert.get("rule") or {}
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}

    severity = rule.get("severity") or "N/A"

    security_severity = (
        rule.get("security_severity_level")
        or alert.get("security_severity_level")
        or "N/A"
    )

    ref = instance.get("ref") or "N/A"

    return {
        "Repository": get_repository(alert),
        "Alert ID": str(alert.get("number") or "N/A"),
        "Rule ID": str(rule.get("id") or "N/A"),
        "Rule Name": str(rule.get("name") or "N/A"),
        "Rule Description": str(rule.get("description") or "N/A"),
        "Severity": str(severity),
        "Security Severity": str(security_severity),
        "File": str(location.get("path") or "N/A"),
        "Start Line": str(location.get("start_line") or "N/A"),
        "End Line": str(location.get("end_line") or "N/A"),
        "State": str(alert.get("state") or "N/A"),
        "Assignee / Owner": get_assignees(alert),
        "Dismissed By": get_dismissed_by(alert),
        "Dismissed At": str(alert.get("dismissed_at") or "N/A"),
        "Dismissal Reason": str(
            alert.get("dismissed_reason") or "N/A"
        ),
        "Triage Comment": str(
            alert.get("dismissed_comment") or "N/A"
        ),
        "Commit SHA": str(
            instance.get("commit_sha") or "N/A"
        ),
        "Branch / Ref": ref,
        "Alert URL": str(alert.get("html_url") or "N/A"),
    }


# ---------------------------------------------------------------------------
# API URL construction
# ---------------------------------------------------------------------------

def normalize_api_base(api_base: str) -> str:
    return api_base.rstrip("/")


def get_alerts_url(
    api_base: str,
    org: Optional[str],
    owner: Optional[str],
    repo: Optional[str],
) -> str:

    base = normalize_api_base(api_base)

    if org:
        return f"{base}/orgs/{org}/code-scanning/alerts"

    if owner and repo:
        return f"{base}/repos/{owner}/{repo}/code-scanning/alerts"

    raise ValueError(
        "Either --org or both --owner and --repo are required."
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_alerts(
    session: requests.Session,
    api_base: str,
    org: Optional[str],
    owner: Optional[str],
    repo: Optional[str],
    output_file: Path,
) -> int:

    url = get_alerts_url(
        api_base=api_base,
        org=org,
        owner=owner,
        repo=repo,
    )

    # Ask GitHub to return CodeQL alerts only.
    params: Dict[str, Any] = {
        "tool_name": "CodeQL",
        "direction": "desc",
        "sort": "updated",
    }

    total_codeql = 0
    total_cpp = 0

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Write atomically:
    # create temporary file in the same directory,
    # then rename after successful completion.
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{output_file.name}.",
        suffix=".tmp",
        dir=str(output_file.parent),
        text=True,
    )

    os.close(fd)

    temp_path = Path(temp_name)

    try:
        with temp_path.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as csv_file:

            writer = csv.DictWriter(
                csv_file,
                fieldnames=CSV_COLUMNS,
                extrasaction="ignore",
            )

            writer.writeheader()

            for alert in paginate(
                session=session,
                url=url,
                params=params,
            ):
                total_codeql += 1

                # Explicitly ensure this is CodeQL.
                tool = alert.get("tool") or {}
                tool_name = str(tool.get("name") or "")

                if tool_name.lower() != "codeql":
                    continue

                # C/C++ CodeQL rules use the cpp/ query namespace.
                if not is_cpp_codeql_alert(alert):
                    continue

                row = alert_to_row(alert)

                writer.writerow(row)

                total_cpp += 1

                if total_cpp % 100 == 0:
                    logger.info(
                        "Exported %d C/C++ alerts...",
                        total_cpp,
                    )

        # Atomic replacement
        temp_path.replace(output_file)

    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass

        raise

    logger.info(
        "CodeQL alerts received: %d",
        total_codeql,
    )

    logger.info(
        "C/C++ alerts exported: %d",
        total_cpp,
    )

    logger.info(
        "CSV: %s",
        output_file.resolve(),
    )

    return total_cpp


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export GitHub CodeQL C/C++ code scanning alerts "
            "including triage comments and assignees."
        )
    )

    parser.add_argument(
        "--api-base",
        default=os.getenv(
            "GITHUB_API_BASE",
            "https://api.github.com",
        ),
        help=(
            "GitHub API base URL. "
            "Can also be supplied through GITHUB_API_BASE."
        ),
    )

    scope = parser.add_mutually_exclusive_group(required=True)

    scope.add_argument(
        "--org",
        help="GitHub organization name.",
    )

    scope.add_argument(
        "--owner",
        help="Repository owner.",
    )

    parser.add_argument(
        "--repo",
        help=(
            "Repository name. Required when --owner is used."
        ),
    )

    parser.add_argument(
        "--output",
        default="github-codeql-cpp-alerts.csv",
        help="Output CSV file.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.verbose)

    if args.owner and not args.repo:
        parser.error(
            "--repo is required when --owner is specified."
        )

    token = os.getenv("GITHUB_TOKEN")

    if not token:
        logger.error(
            "GITHUB_TOKEN environment variable is not set."
        )
        logger.error(
            "Do not hard-code the GitHub token in this script."
        )
        return 2

    try:
        session = create_session(token)

        count = export_alerts(
            session=session,
            api_base=args.api_base,
            org=args.org,
            owner=args.owner,
            repo=args.repo,
            output_file=Path(args.output),
        )

        if count == 0:
            logger.warning(
                "No C/C++ CodeQL alerts were exported."
            )

        return 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user.")
        return 130

    except Exception as exc:
        logger.error("Export failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
