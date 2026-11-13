#!/usr/bin/env python3
"""Tag release gates and draft-first publication. No signing secrets are read here."""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import time


def run(*args, data=None):
    return subprocess.check_output(args, input=data, text=True)


def api(path, method="GET", payload=None):
    args = ["gh", "api", path, "--method", method]
    if payload is not None:
        args += ["--input", "-"]
    return json.loads(run(*args, data=json.dumps(payload) if payload is not None else None))


def version(tag):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag):
        raise ValueError("Release tag must be vMAJOR.MINOR.PATCH")
    return tag[1:]


def validate_ci(runs, sha):
    matching = [r for r in runs if r["head_sha"] == sha
                and r["event"] == "push" and r["head_branch"] == "main"]
    if not matching:
        return None
    latest = max(matching, key=lambda r: r["id"])
    if latest["status"] != "completed":
        return None
    if latest["conclusion"] != "success":
        raise ValueError("The tagged commit's latest main CI did not pass")
    return latest["id"]


def validate_jobs(jobs):
    for name in ("rust-linux", "macos"):
        found = [j for j in jobs if j["name"] == name]
        if not found or any(j["conclusion"] != "success" for j in found):
            raise ValueError("Required CI job missing or unsuccessful: " + name)


def check(repo, sha, tag):
    expected = version(tag)
    with open("Sources/App/Info.plist", "rb") as source:
        if plistlib.load(source)["CFBundleShortVersionString"] != expected:
            raise ValueError("Tag and App version differ")
    if run("git", "rev-parse", "HEAD").strip() != sha:
        raise ValueError("Checkout is not the tagged commit")
    if api(f"repos/{repo}/commits/{tag}")["sha"] != sha:
        raise ValueError("Release tag no longer points to this commit")
    subprocess.run(["git", "merge-base", "--is-ancestor", sha, "origin/main"], check=True)
    deadline = time.monotonic() + 2100
    while time.monotonic() < deadline:
        runs = api(f"repos/{repo}/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha={sha}&per_page=100")
        run_id = validate_ci(runs["workflow_runs"], sha)
        if run_id is not None:
            jobs = api(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]
            validate_jobs(jobs)
            print("Tagged commit is on main and both required CI jobs passed")
            return
        print("Waiting for the tagged commit's main CI", flush=True)
        time.sleep(20)
    raise TimeoutError("No successful main CI within the release gate deadline")


def validate_draft(existing, sha):
    if not existing["draft"]:
        raise ValueError("Published releases are immutable; choose a new version")
    if existing["target_commitish"] != sha:
        raise ValueError("Existing draft belongs to a different commit")


def verify_downloads(files, directory):
    for source in files:
        received = directory / source.name
        if not received.is_file() or hashlib.sha256(received.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
            raise ValueError("Downloaded release asset differs: " + source.name)


def publish(repo, sha, tag):
    number = version(tag)
    if api(f"repos/{repo}/commits/{tag}")["sha"] != sha:
        raise ValueError("Release tag no longer points to this commit")
    folder = Path(".local-build")
    archive = folder / f"AlwaysConnect-{number}-macos-arm64.zip"
    files = [archive, Path(str(archive) + ".sha256"), folder / f"AlwaysConnect-{number}-third-party-sources.tar.gz"]
    if any(not p.is_file() or not p.stat().st_size for p in files):
        raise ValueError("All three release assets are required")
    # The API call must succeed; an authentication failure never means 'no release'.
    pages = json.loads(run("gh", "api", f"repos/{repo}/releases?per_page=100", "--paginate", "--slurp"))
    releases = [r for page in pages for r in page]
    published = []
    for item in releases:
        if not item["draft"] and not item.get("prerelease", False):
            try:
                published.append(tuple(map(int, version(item["tag_name"]).split("."))))
            except ValueError:
                pass
    if published and tuple(map(int, number.split("."))) <= max(published):
        raise ValueError("New stable release must be newer than published versions")
    matches = [r for r in releases if r["tag_name"] == tag]
    if matches:
        release = matches[0]
        validate_draft(release, sha)
    else:
        release = api(f"repos/{repo}/releases", "POST", {
            "tag_name": tag, "target_commitish": sha, "name": "AlwaysConnect " + number,
            "draft": True, "prerelease": False, "generate_release_notes": True,
            "body": "自动检查通过后构建；真实网络待测项见仓库实测清单。",
        })
    run("gh", "release", "upload", tag, *(str(p) for p in files), "--clobber", "--repo", repo)
    current = api(f"repos/{repo}/releases/{release['id']}")
    validate_draft(current, sha)
    if {a["name"] for a in current["assets"]} != {p.name for p in files}:
        raise ValueError("Draft has unexpected or missing assets")
    with tempfile.TemporaryDirectory(prefix="release-download-") as scratch:
        run("gh", "release", "download", tag, "--repo", repo, "--dir", scratch)
        verify_downloads(files, Path(scratch))
    if api(f"repos/{repo}/commits/{tag}")["sha"] != sha:
        raise ValueError("Release tag changed while packaging")
    result = api(f"repos/{repo}/releases/{release['id']}", "PATCH", {"draft": False, "make_latest": "true"})
    if result["draft"] or result["tag_name"] != tag:
        raise ValueError("Release publication was not confirmed")
    print("Published " + result["html_url"])


if __name__ == "__main__":
    action, repository, commit, release_tag = sys.argv[1:]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid repository or commit")
    {"check": check, "publish": publish}[action](repository, commit, release_tag)
