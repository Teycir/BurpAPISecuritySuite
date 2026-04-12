from scripts.sync_readme_updates import (
    END_MARKER,
    Release,
    START_MARKER,
    parse_changelog,
    render_recent_updates,
    replace_managed_block,
    sync_readme,
)


def test_parse_changelog_collects_ordered_releases_and_section_prefixed_bullets():
    changelog = """
# Changelog

## [2.0.0] - 2026-01-02
### Added
- New scanner tab
### Fixed
- Crash in parser

## [1.9.9] - 2026-01-01
### Changed
- Tuning defaults
"""
    releases = parse_changelog(changelog, max_releases=2)
    assert [r.version for r in releases] == ["2.0.0", "1.9.9"]
    assert releases[0].bullets == ["Added: New scanner tab", "Fixed: Crash in parser"]
    assert releases[1].bullets == ["Changed: Tuning defaults"]


def test_replace_managed_block_updates_only_marker_region():
    readme = """
## Updates

### Recent Updates

<!-- recent-updates:start -->
old content
<!-- recent-updates:end -->

### v1.0.0 - legacy
- keep legacy notes
"""
    rendered = "%s\n\n### v2.0.0 - 2026-01-02\n- Added: New scanner tab\n\n%s\n" % (
        START_MARKER,
        END_MARKER,
    )
    updated = replace_managed_block(readme, rendered)

    assert "old content" not in updated
    assert "### v2.0.0 - 2026-01-02" in updated
    assert "### v1.0.0 - legacy" in updated


def test_sync_readme_writes_rendered_block(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    readme = tmp_path / "README.md"
    changelog.write_text(
        "\n".join(
            [
                "# Changelog",
                "",
                "## [1.0.1] - 2026-01-03",
                "### Added",
                "- New thing",
                "",
                "## [1.0.0] - 2026-01-02",
                "### Fixed",
                "- Bug fix",
            ]
        ),
        encoding="utf-8",
    )
    readme.write_text(
        "\n".join(
            [
                "# Project",
                "",
                "## Updates",
                "",
                "### Recent Updates",
                "",
                "<!-- recent-updates:start -->",
                "stale",
                "<!-- recent-updates:end -->",
            ]
        ),
        encoding="utf-8",
    )

    changed = sync_readme(changelog, readme, releases_count=2)
    content = readme.read_text(encoding="utf-8")
    assert changed == 1
    assert "### v1.0.1 - 2026-01-03" in content
    assert "- Added: New thing" in content
    assert "stale" not in content
    assert START_MARKER in content and END_MARKER in content

    changed_again = sync_readme(changelog, readme, releases_count=2)
    assert changed_again == 0


def test_render_recent_updates_limits_bullet_count():
    rendered = render_recent_updates(
        releases=[Release(version="1.0.0", date="2026-01-01", bullets=["a", "b", "c", "d", "e"])],
        max_bullets_per_release=3,
    )
    assert "- a" in rendered
    assert "- c" in rendered
    assert "- d" not in rendered
