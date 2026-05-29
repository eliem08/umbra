"""
Configurable authentication-detection patterns.

The original parser hardcoded a handful of auth keywords. Enterprise codebases
use bespoke decorators (`@gatekeeper`), custom dependency callables
(`require_scopes(...)`), and framework-specific annotations. A false negative
here means an unauthenticated endpoint is reported as "safe" — unacceptable for
a SOC 2 / ISO 27001 gate. `AuthConfig` lets a project declare exactly what
"authenticated" looks like, via a `.shadowscan.yml` / `.shadowscan.json` file.
"""
from __future__ import annotations

import json
import os
import re
from typing import List, Optional, Set

from pydantic import BaseModel, Field

CONFIG_FILENAMES = (".shadowscan.yml", ".shadowscan.yaml", ".shadowscan.json")


class AuthConfig(BaseModel):
    """
    Declares the signals that mark an endpoint as authenticated, per language.

    Matching is case-insensitive and substring-based for keywords, exact-ish
    (substring) for callables/annotations so wrappers still match.
    """

    # Generic substrings searched in decorator/function/middleware names across
    # all languages. Keep this conservative to avoid false positives.
    keywords: Set[str] = Field(
        default_factory=lambda: {
            "jwt", "login", "auth", "token", "security",
            "permission", "verify", "secure",
        }
    )

    # Python: callables that, when used as a parameter default or in a route's
    # `dependencies=[...]`, indicate an auth dependency (FastAPI Depends/Security).
    python_dependency_callables: Set[str] = Field(
        default_factory=lambda: {"Depends", "Security"}
    )

    # Python: substrings that mark a *dependency callable* as authentication
    # related. A bare `Depends(get_db)` is NOT auth; `Depends(get_current_user)`
    # is. Matched against the callable name referenced inside Depends/Security and
    # against `Annotated[...]` alias names. Combined with `keywords` at match time.
    python_auth_dependency_hints: Set[str] = Field(
        default_factory=lambda: {
            "current_user", "currentuser", "current_active", "get_current",
            "active_user", "authenticated", "oauth", "apikey", "api_key",
            "bearer", "scope", "principal",
        }
    )

    # Java/Spring: annotations that enforce authorization on a handler or class.
    spring_auth_annotations: Set[str] = Field(
        default_factory=lambda: {
            "PreAuthorize", "PostAuthorize", "Secured",
            "RolesAllowed", "PreFilter", "PostFilter",
        }
    )

    # JS/Express: middleware identifiers that perform authentication when passed
    # as a handler argument (e.g. `router.get('/x', requireAuth, handler)`).
    express_auth_middleware: Set[str] = Field(
        default_factory=lambda: {
            "auth", "authenticate", "requireauth", "requirelogin",
            "ensureauthenticated", "ensureloggedin", "isauthenticated",
            "passport", "verifytoken", "checkjwt", "jwtcheck",
            "protect", "authguard", "authorize",
        }
    )

    def keyword_match(self, name: Optional[str]) -> bool:
        if not name:
            return False
        low = name.lower()
        return any(kw in low for kw in self.keywords)

    def python_dependency_match(self, unparsed_default: str) -> bool:
        return any(callable_ in unparsed_default for callable_ in self.python_dependency_callables)

    def _dep_callable_is_auth(self, callable_name: Optional[str]) -> bool:
        """True if a dependency callable's name looks auth-related (keywords + hints)."""
        if not callable_name:
            return False
        low = callable_name.lower()
        if any(kw in low for kw in self.keywords):
            return True
        return any(h in low for h in self.python_auth_dependency_hints)

    def python_auth_expr_match(self, expr: str, auth_aliases: Optional[Set[str]] = None) -> bool:
        """
        Decide whether a parameter expression (default OR annotation) implies auth.

        - References to a known auth alias (e.g. `CurrentUser`) -> auth.
        - `Depends(<callable>)` / `Security(<callable>)` where the callable name is
          auth-related -> auth. A generic `Depends(get_db)` does NOT count.
        """
        if not expr:
            return False
        if auth_aliases:
            # Word-boundary match so `CurrentUser` doesn't match `CurrentUserList`.
            for alias in auth_aliases:
                if re.search(rf"\b{re.escape(alias)}\b", expr):
                    return True
        for callable_, name in re.findall(r"\b(Depends|Security)\(\s*([A-Za-z_][\w\.]*)", expr):
            if self._dep_callable_is_auth(name):
                return True
        return False

    def spring_annotation_match(self, annotation: Optional[str]) -> bool:
        if not annotation:
            return False
        low = annotation.lower()
        return any(a.lower() in low for a in self.spring_auth_annotations)

    def express_middleware_match(self, identifier: Optional[str]) -> bool:
        if not identifier:
            return False
        low = identifier.lower()
        # Match against the explicit middleware list OR the generic keywords.
        if any(mw in low for mw in self.express_auth_middleware):
            return True
        return self.keyword_match(identifier)


def _read_config_file(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()
    if filepath.endswith((".yml", ".yaml")):
        try:
            import yaml  # type: ignore
        except ImportError as e:  # pragma: no cover - depends on optional dep
            raise ValueError(
                f"Cannot read YAML config {filepath}: PyYAML is not installed. "
                f"Install it or use a .shadowscan.json file."
            ) from e
        return yaml.safe_load(raw) or {}
    return json.loads(raw) if raw.strip() else {}


def load_auth_config(path: Optional[str] = None) -> AuthConfig:
    """
    Loads an AuthConfig.

    - If `path` points to a config file, load it directly.
    - If `path` is a directory (or None -> cwd), search it for a known config
      filename.
    - If nothing is found, return defaults.

    Set fields are *merged* over the defaults so a project can extend the
    built-in keyword lists rather than replace them, by using the `extend_*`
    convention: keys prefixed with `extend_` are unioned into the defaults.
    """
    config_path: Optional[str] = None

    # Treat `path` as an explicit config file only if it is actually a config
    # file (by name or by .json/.yml/.yaml extension) — never a scanned source file.
    is_config_file = bool(path) and os.path.isfile(path) and (
        os.path.basename(path) in CONFIG_FILENAMES or path.endswith((".json", ".yml", ".yaml"))
    )

    if is_config_file:
        config_path = path
    else:
        if path and os.path.isfile(path):
            search_dir = os.path.dirname(os.path.abspath(path))
        elif path and os.path.isdir(path):
            search_dir = path
        else:
            search_dir = os.getcwd()
        for name in CONFIG_FILENAMES:
            candidate = os.path.join(search_dir, name)
            if os.path.exists(candidate):
                config_path = candidate
                break

    if not config_path:
        return AuthConfig()

    data = _read_config_file(config_path)
    auth_section = data.get("auth", data) if isinstance(data, dict) else {}

    defaults = AuthConfig()
    extend_keys = {k[len("extend_"):]: v for k, v in auth_section.items() if k.startswith("extend_")}
    replace_keys = {k: v for k, v in auth_section.items() if not k.startswith("extend_")}

    merged: dict = {}
    for field_name in AuthConfig.model_fields:
        default_val = getattr(defaults, field_name)
        if field_name in replace_keys:
            merged[field_name] = replace_keys[field_name]
        elif field_name in extend_keys and isinstance(default_val, set):
            merged[field_name] = set(default_val) | set(extend_keys[field_name])
        else:
            merged[field_name] = default_val

    return AuthConfig(**merged)
