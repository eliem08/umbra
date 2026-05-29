"""
Git provenance for endpoints — the "introduced this week" capability.

Given a scanned set of routes and a git window (a relative/absolute date such
as ``"1 week ago"`` or a baseline revision such as ``"origin/main"``), this
module attributes each endpoint to the commit that last touched its definition
line and flags the ones that fall inside the window. That powers both the CLI
``--since`` filter and the MCP "endpoints introduced this week that lack auth"
query.

Implementation is pure ``git`` plumbing via subprocess — no extra dependency.
"""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from .schemas import RouteEndpoint

_SHA_HEADER_RE = re.compile(r"^([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$")


class GitInspector:
    """Thin wrapper over the ``git`` CLI scoped to a single repository."""

    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self._toplevel: Optional[str] = None
        self._blame_cache: Dict[str, Dict[int, str]] = {}
        self._commit_meta: Dict[str, Dict[str, str]] = {}

    # --- low-level ---
    def _run(self, args: List[str]) -> str:
        result = subprocess.run(
            ["git", "-C", self.repo_path, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout

    def is_repo(self) -> bool:
        try:
            self._run(["rev-parse", "--is-inside-work-tree"])
            return True
        except (GitError, FileNotFoundError):
            return False

    def toplevel(self) -> str:
        if self._toplevel is None:
            self._toplevel = self._run(["rev-parse", "--show-toplevel"]).strip()
        return self._toplevel

    def _is_revision(self, ref: str) -> bool:
        """True if `ref` resolves to a git object (baseline ref) rather than a date."""
        try:
            self._run(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
            return True
        except GitError:
            return False

    # --- window resolution ---
    def recent_commits(self, since: str) -> Set[str]:
        """Full SHAs of commits inside the window (baseline ref range or --since date)."""
        if self._is_revision(since):
            out = self._run(["rev-list", f"{since}..HEAD"])
        else:
            out = self._run(["rev-list", f"--since={since}", "HEAD"])
        return {line.strip() for line in out.splitlines() if line.strip()}

    def added_files(self, since: str) -> Set[str]:
        """Repo-relative paths of files *added* (not just modified) within the window."""
        if self._is_revision(since):
            out = self._run(["diff", "--name-only", "--diff-filter=A", f"{since}..HEAD"])
        else:
            out = self._run([
                "log", f"--since={since}", "--diff-filter=A",
                "--name-only", "--pretty=format:",
            ])
        return {line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()}

    # --- blame ---
    def blame_line_commit(self, repo_rel_path: str, line_number: int) -> Optional[str]:
        """Return the full SHA of the commit that last touched the given line."""
        line_map = self._blame_file(repo_rel_path)
        return line_map.get(line_number)

    def _blame_file(self, repo_rel_path: str) -> Dict[int, str]:
        if repo_rel_path in self._blame_cache:
            return self._blame_cache[repo_rel_path]

        line_map: Dict[int, str] = {}
        try:
            out = self._run(["blame", "--porcelain", "--", repo_rel_path])
        except GitError:
            self._blame_cache[repo_rel_path] = line_map
            return line_map

        current_sha: Optional[str] = None
        for raw in out.splitlines():
            header = _SHA_HEADER_RE.match(raw)
            if header:
                current_sha = header.group(1)
                final_line = int(header.group(3))
                self._commit_meta.setdefault(current_sha, {})
                self._commit_meta[current_sha]["_pending_line"] = str(final_line)
            elif current_sha and raw.startswith("author "):
                self._commit_meta[current_sha].setdefault("author", raw[len("author "):].strip())
            elif current_sha and raw.startswith("author-time "):
                self._commit_meta[current_sha].setdefault("author_time", raw[len("author-time "):].strip())
            elif current_sha and raw.startswith("\t"):
                pending = self._commit_meta[current_sha].pop("_pending_line", None)
                if pending is not None:
                    line_map[int(pending)] = current_sha

        self._blame_cache[repo_rel_path] = line_map
        return line_map

    def commit_meta(self, sha: str) -> Dict[str, str]:
        meta = self._commit_meta.get(sha, {})
        author = meta.get("author")
        author_time = meta.get("author_time")
        committed_at = None
        if author_time:
            try:
                committed_at = datetime.fromtimestamp(int(author_time), tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                committed_at = None
        return {"author": author, "committed_at": committed_at, "short_sha": sha[:10]}


class GitError(RuntimeError):
    pass


def annotate_new_endpoints(
    routes: List[RouteEndpoint],
    repo_path: str,
    since: str,
) -> List[RouteEndpoint]:
    """
    Mark routes introduced/changed within the git window in place.

    `repo_path` is the directory that was scanned; `source_file` on each route is
    relative to it. Routes are mapped to repo-relative paths so git can blame
    them. Returns the subset of routes flagged as new.
    """
    inspector = GitInspector(repo_path)
    if not inspector.is_repo():
        raise GitError(f"{repo_path} is not inside a git work tree")

    toplevel = inspector.toplevel()
    recent = inspector.recent_commits(since)
    added = inspector.added_files(since)

    new_routes: List[RouteEndpoint] = []
    for route in routes:
        abs_src = os.path.abspath(os.path.join(repo_path, route.source_file))
        repo_rel = os.path.relpath(abs_src, toplevel).replace("\\", "/")

        sha = inspector.blame_line_commit(repo_rel, route.line_number)
        if not sha or sha not in recent:
            continue

        meta = inspector.commit_meta(sha)
        route.is_new = True
        route.commit = meta["short_sha"]
        route.author = meta["author"]
        route.committed_at = meta["committed_at"]
        route.change_type = "added" if repo_rel in added else "modified"
        new_routes.append(route)

    return new_routes
