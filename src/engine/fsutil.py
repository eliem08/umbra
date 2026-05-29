"""Shared filesystem walking with sensible default exclusions.

Dogfooding against real repos showed the scanner wading through `node_modules`,
virtualenvs, build output, and test/example trees — producing noise (routes
defined in tests) and, for `node_modules`, huge slowdowns. These directories are
pruned by default; callers can override.
"""
from __future__ import annotations

import os
from typing import Iterator, Optional, Sequence, Set, Tuple

DEFAULT_EXCLUDE_DIRS: Set[str] = {
    # VCS / tooling
    ".git", ".hg", ".svn", ".idea", ".vscode",
    # Python
    "__pycache__", ".venv", "venv", "env", ".env", ".tox", ".mypy_cache",
    ".pytest_cache", "site-packages", ".eggs", "build", "dist",
    # JS / Java build & deps
    "node_modules", "bower_components", "target", ".gradle", "out",
    # Test / example trees (route defs here are not production surface)
    "tests", "test", "__tests__", "examples", "example", "fixtures",
}


def iter_source_files(
    base_dir: str,
    extensions: Tuple[str, ...],
    exclude_dirs: Optional[Set[str]] = None,
) -> Iterator[Tuple[str, str]]:
    """
    Yield (full_path, rel_path) for files under `base_dir` matching `extensions`,
    pruning excluded directories. rel_path uses forward slashes.
    """
    excludes = DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs
    base_dir = os.path.abspath(base_dir)

    if os.path.isfile(base_dir):
        if base_dir.lower().endswith(extensions):
            yield base_dir, os.path.basename(base_dir)
        return

    for root, dirs, files in os.walk(base_dir):
        # Prune excluded directories in place so os.walk doesn't descend into them.
        dirs[:] = [d for d in dirs if d not in excludes]
        for file in files:
            if file.lower().endswith(extensions):
                full = os.path.join(root, file)
                rel = os.path.relpath(full, base_dir).replace("\\", "/")
                yield full, rel
