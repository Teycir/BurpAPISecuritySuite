#!/usr/bin/env python3
"""Sync README Recent Updates from CHANGELOG releases.

Usage:
    python3 scripts/sync_readme_updates.py
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

START_MARKER = "<!-- recent-updates:start -->"
END_MARKER = "<!-- recent-updates:end -->"

VERSION_RE = re.compile(r"^## \[(?P<version>[^\]]+)\] - (?P<date>\d{4}-\d{2}-\d{2})\s*$")
SUBSECTION_RE = re.compile(r"^### (?P<name>.+?)\s*$")


@dataclass
class Release:
    version: str
    date: str
    bullets: List[str]


def parse_changelog(changelog_text: str, max_releases: int) -> List[Release]:
    lines = changelog_text.splitlines()
    releases: List[Release] = []
    i = 0
    while i < len(lines) and len(releases) < max_releases:
        match = VERSION_RE.match(lines[i])
        if not match:
            i += 1
            continue

        version = match.group("version")
        date = match.group("date")
        i += 1

        current_section = ""
        bullets: List[str] = []

        while i < len(lines):
            if VERSION_RE.match(lines[i]):
                break

            subsection_match = SUBSECTION_RE.match(lines[i])
            if subsection_match:
                current_section = subsection_match.group("name")
                i += 1
                continue

            line = lines[i]
            if line.startswith("- "):
                bullet = line[2:].strip()
                if current_section:
                    bullets.append("%s: %s" % (current_section, bullet))
                else:
                    bullets.append(bullet)
            i += 1

        releases.append(Release(version=version, date=date, bullets=bullets))

    return releases


def render_recent_updates(releases: List[Release], max_bullets_per_release: int = 4) -> str:
    output_lines = [START_MARKER, ""]
    for release in releases:
        output_lines.append("### v%s - %s" % (release.version, release.date))
        selected_bullets = release.bullets[:max_bullets_per_release]
        if selected_bullets:
            for bullet in selected_bullets:
                output_lines.append("- %s" % bullet.rstrip(":"))
        else:
            output_lines.append("- No categorized changes listed.")
        output_lines.append("")
    output_lines.append(END_MARKER)
    return "\n".join(output_lines).rstrip() + "\n"


def replace_managed_block(readme_text: str, rendered_block: str) -> str:
    marker_re = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        flags=re.DOTALL,
    )
    if marker_re.search(readme_text):
        return marker_re.sub(rendered_block.rstrip("\n"), readme_text, count=1)

    anchor = "### Recent Updates"
    anchor_idx = readme_text.find(anchor)
    if anchor_idx < 0:
        raise ValueError("Could not find '### Recent Updates' heading in README.")

    insert_at = anchor_idx + len(anchor)
    return readme_text[:insert_at] + "\n\n" + rendered_block + readme_text[insert_at:]


def sync_readme(changelog_path: Path, readme_path: Path, releases_count: int) -> int:
    changelog_text = changelog_path.read_text(encoding="utf-8")
    readme_text = readme_path.read_text(encoding="utf-8")

    releases = parse_changelog(changelog_text, max_releases=releases_count)
    if not releases:
        raise ValueError("No releases found in changelog.")

    rendered_block = render_recent_updates(releases)
    updated_readme = replace_managed_block(readme_text, rendered_block)

    if updated_readme != readme_text:
        readme_path.write_text(updated_readme, encoding="utf-8")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sync README Recent Updates from CHANGELOG.")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to changelog file.")
    parser.add_argument("--readme", default="README.md", help="Path to README file.")
    parser.add_argument(
        "--releases",
        type=int,
        default=4,
        help="Number of latest releases to include in README Recent Updates.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.releases < 1:
        parser.error("--releases must be >= 1")

    return sync_readme(
        changelog_path=Path(args.changelog),
        readme_path=Path(args.readme),
        releases_count=args.releases,
    )


if __name__ == "__main__":
    raise SystemExit(main())
