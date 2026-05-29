import ast
import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Set, Dict
from .schemas import RouteEndpoint, ScanResult
from .authconfig import AuthConfig
from .fsutil import iter_source_files, DEFAULT_EXCLUDE_DIRS

# Common HTTP methods to match in decorators
HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "route", "api_route"}
VERB_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}
# Default auth keywords, retained for backwards compatibility. Detection is now
# driven by AuthConfig; this constant mirrors the AuthConfig defaults.
AUTH_KEYWORDS = AuthConfig().keywords

# Use parallel parsing only above this many files (process pool startup isn't
# worth it for small scans, which is the common case for a single service).
_PARALLEL_THRESHOLD = 300


def normalize_path(path: str) -> str:
    """
    Standardizes endpoint paths to a canonical colon-prefixed format (e.g., /users/:id).
    Removes trailing slashes (except root).
    """
    if not path:
        return "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    # Flask-style <[type:]name> -> :name ; FastAPI-style {name} -> :name
    path = re.sub(r"<(?:\w+:)?(\w+)>", r":\1", path)
    path = re.sub(r"\{(\w+)\}", r":\1", path)
    return path


# --------------------------------------------------------------------------- #
# Module-level AST helpers (free functions so they are usable from worker procs)
# --------------------------------------------------------------------------- #
def _get_name_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        val = _get_name_str(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    return None


def _parse_decorator(decorator: ast.AST) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """@app.get("/users") -> ("app", "get", "/users")"""
    func = decorator.func if isinstance(decorator, ast.Call) else decorator
    caller = attr = path = None
    if isinstance(func, ast.Attribute):
        caller = _get_name_str(func.value)
        attr = func.attr
    elif isinstance(func, ast.Name):
        attr = func.id
    if isinstance(decorator, ast.Call):
        if decorator.args:
            first = decorator.args[0]
            if isinstance(first, ast.Constant):
                path = str(first.value)
        else:
            for kw in decorator.keywords:
                if kw.arg in ("path", "rule") and isinstance(kw.value, ast.Constant):
                    path = str(kw.value.value)
    return caller, attr, path


def _extract_methods(decorator: ast.AST, attr: str) -> List[str]:
    if attr.lower() in VERB_METHODS:
        return [attr.upper()]
    if isinstance(decorator, ast.Call):
        for kw in decorator.keywords:
            if kw.arg == "methods":
                val = kw.value
                if isinstance(val, (ast.List, ast.Set, ast.Tuple)):
                    return [str(el.value).upper() for el in val.elts if isinstance(el, ast.Constant)]
                if isinstance(val, ast.Constant):
                    return [str(val.value).upper()]
    return ["GET"]


# --------------------------------------------------------------------------- #
# Plain, picklable per-file extraction result (no AST nodes -> safe across procs)
# --------------------------------------------------------------------------- #
@dataclass
class RouteCandidate:
    caller: str
    raw_path: str
    methods: List[str]
    line_number: int
    framework: str
    local_prefix: str
    auth_local: bool
    auth_info: Optional[str]
    # Annotation/default/dependency expression strings to recheck against global
    # auth aliases in phase 2 (only retained when auth wasn't already established).
    alias_exprs: List[str] = field(default_factory=list)


@dataclass
class FileScanResult:
    rel_path: str
    include_prefixes: Dict[str, str]
    alias_names: Set[str]
    candidates: List[RouteCandidate]


def _extract_file(args: Tuple[str, str, AuthConfig]) -> FileScanResult:
    """
    Parse a single file ONCE, walk it ONCE, and extract everything needed:
    framework hints, router prefixes, auth-dependency aliases, and route
    candidates with their auth signals. Returns plain data so it can cross a
    process boundary. Auth that depends on cross-file aliases is deferred: each
    candidate keeps the expression strings for phase-2 resolution.
    """
    filepath, rel_path, auth_config = args
    empty = FileScanResult(rel_path, {}, set(), [])
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except Exception:
        return empty

    has_flask = has_fastapi = False
    local_prefixes: Dict[str, str] = {}
    include_prefixes: Dict[str, str] = {}
    alias_names: Set[str] = set()
    func_nodes: List[ast.AST] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                if "flask" in name.name:
                    has_flask = True
                if "fastapi" in name.name:
                    has_fastapi = True
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                if "flask" in node.module:
                    has_flask = True
                if "fastapi" in node.module:
                    has_fastapi = True
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("register_blueprint", "include_router"):
                if node.args:
                    var = _get_name_str(node.args[0])
                    if var:
                        pkw = "prefix" if func.attr == "include_router" else "url_prefix"
                        for kw in node.keywords:
                            if kw.arg == pkw and isinstance(kw.value, ast.Constant):
                                include_prefixes[var] = str(kw.value.value)
                                break
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            tgt = node.targets[0].id
            val = node.value
            if isinstance(val, ast.Call):
                ctor = _get_name_str(val.func) or ""
                if ctor.endswith("APIRouter") or ctor.endswith("Blueprint"):
                    for kw in val.keywords:
                        if kw.arg in ("prefix", "url_prefix") and isinstance(kw.value, ast.Constant):
                            local_prefixes[tgt] = str(kw.value.value)
            # Auth-dependency alias: NAME = Annotated[..., Depends(auth)] / Depends(auth).
            if isinstance(val, (ast.Call, ast.Subscript)):
                try:
                    rhs = ast.unparse(val)
                except Exception:
                    rhs = ""
                if auth_config.python_auth_expr_match(rhs):
                    alias_names.add(tgt)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
            func_nodes.append(node)

    candidates: List[RouteCandidate] = []
    for node in func_nodes:
        route_decorators: List[Tuple[ast.AST, str, str, str]] = []
        auth_decorators: List[str] = []
        for dec in node.decorator_list:
            caller, attr, path = _parse_decorator(dec)
            if attr and attr.lower() in HTTP_METHODS:
                if path is not None:
                    route_decorators.append((dec, caller or "", attr, path))
            elif attr:
                if auth_config.keyword_match(attr):
                    auth_decorators.append(attr)
            elif isinstance(dec, ast.Name):
                if auth_config.keyword_match(dec.id):
                    auth_decorators.append(dec.id)

        if not route_decorators:
            continue

        framework = "FastAPI"
        if has_flask and not has_fastapi:
            framework = "Flask"
        else:
            for _, caller, attr, _ in route_decorators:
                if "bp" in caller.lower() or "blueprint" in caller.lower():
                    framework = "Flask"
                    break
                if attr == "route" and not has_fastapi:
                    framework = "Flask"

        # Function-level auth signals (annotations + defaults). `auth_config` only
        # resolves the callable-based part here; alias references are kept as
        # strings for phase 2 since aliases are a cross-file fact.
        sig_auth = False
        sig_info: Optional[str] = None
        sig_exprs: List[str] = []
        all_args = list(node.args.args) + list(node.args.posonlyargs) + list(node.args.kwonlyargs)
        for arg in all_args:
            if arg.annotation is not None:
                try:
                    ann = ast.unparse(arg.annotation)
                except Exception:
                    ann = ""
                if ann:
                    sig_exprs.append(ann)
                    if not sig_auth and auth_config.python_auth_expr_match(ann):
                        sig_auth = True
                        sig_info = f"Argument {arg.arg} annotation: {ann}"
        pos_args = node.args.args
        defaults = node.args.defaults
        offset = len(pos_args) - len(defaults)
        default_pairs = [(pos_args[offset + i].arg, d) for i, d in enumerate(defaults)]
        default_pairs += [(a.arg, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d]
        for arg_name, dval in default_pairs:
            try:
                uval = ast.unparse(dval)
            except Exception:
                uval = ""
            if uval:
                sig_exprs.append(uval)
                if not sig_auth and auth_config.python_auth_expr_match(uval):
                    sig_auth = True
                    sig_info = f"Argument {arg_name} default: {uval}"

        for dec, caller, attr, path in route_decorators:
            methods = _extract_methods(dec, attr)
            dec_auth = False
            dec_info: Optional[str] = None
            dec_exprs: List[str] = []
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "dependencies":
                        try:
                            ukw = ast.unparse(kw.value)
                        except Exception:
                            ukw = ""
                        if ukw:
                            dec_exprs.append(ukw)
                            if auth_config.python_auth_expr_match(ukw):
                                dec_auth = True
                                dec_info = f"Decorator dependencies: {ukw}"

            auth_local = sig_auth or dec_auth or bool(auth_decorators)
            info_parts = []
            if sig_info:
                info_parts.append(sig_info)
            if dec_info:
                info_parts.append(dec_info)
            if auth_decorators:
                info_parts.append(f"Flask Decorators: {', '.join(auth_decorators)}")
            auth_info = "; ".join(info_parts) if info_parts else None

            candidates.append(RouteCandidate(
                caller=caller,
                raw_path=path,
                methods=methods,
                line_number=node.lineno,
                framework=framework,
                local_prefix=local_prefixes.get(caller, ""),
                auth_local=auth_local,
                auth_info=auth_info,
                # Only keep exprs for later alias resolution if not already authed.
                alias_exprs=[] if auth_local else (sig_exprs + dec_exprs),
            ))

    return FileScanResult(rel_path, include_prefixes, alias_names, candidates)


def _worker_count() -> int:
    override = os.environ.get("SHADOW_SCAN_WORKERS")
    if override:
        try:
            return max(1, int(override))
        except ValueError:
            pass
    return os.cpu_count() or 1


class ASTParser:
    """
    Static analysis parser for FastAPI/Flask. Parses each file exactly once and
    parallelizes across processes for large codebases.
    """
    def __init__(self, base_dir: str, auth_config: Optional[AuthConfig] = None,
                 exclude_dirs: Optional[Set[str]] = None):
        self.base_dir = os.path.abspath(base_dir)
        self.prefix_map: Dict[str, str] = {}
        self.auth_aliases: Set[str] = set()
        self.auth_config = auth_config or AuthConfig()
        self.exclude_dirs = DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs

    def parse_directory(self, files: Optional[List[Tuple[str, str]]] = None) -> ScanResult:
        if files is None:
            files = list(iter_source_files(self.base_dir, (".py",), self.exclude_dirs))

        results = self._extract_all(files)

        # Phase 1 merge: cross-file router prefixes + auth aliases.
        prefix_map: Dict[str, str] = {}
        aliases: Set[str] = set()
        for r in results:
            prefix_map.update(r.include_prefixes)
            aliases |= r.alias_names
        self.prefix_map, self.auth_aliases = prefix_map, aliases

        # Phase 2 resolve: apply prefixes and finalize alias-based auth.
        endpoints: List[RouteEndpoint] = []
        for r in results:
            endpoints.extend(self._finalize(r, prefix_map, aliases))
        return ScanResult(routes=endpoints)

    def _extract_all(self, files: List[Tuple[str, str]]) -> List[FileScanResult]:
        tasks = [(full, rel, self.auth_config) for full, rel in files]
        workers = _worker_count()
        if len(tasks) < _PARALLEL_THRESHOLD or workers <= 1:
            return [_extract_file(t) for t in tasks]
        try:
            chunk = max(1, len(tasks) // (workers * 8))
            with ProcessPoolExecutor(max_workers=workers) as ex:
                return list(ex.map(_extract_file, tasks, chunksize=chunk))
        except Exception:
            # Fall back to serial if the pool can't start (sandboxed envs etc.).
            return [_extract_file(t) for t in tasks]

    def _finalize(self, r: FileScanResult, prefix_map: Dict[str, str], aliases: Set[str]) -> List[RouteEndpoint]:
        out: List[RouteEndpoint] = []
        for c in r.candidates:
            auth = c.auth_local
            info = c.auth_info
            if not auth and aliases:
                for expr in c.alias_exprs:
                    if self.auth_config.python_auth_expr_match(expr, aliases):
                        auth = True
                        info = f"alias dependency: {expr}"
                        break
            combined = prefix_map.get(c.caller, "") + (c.local_prefix or "") + (c.raw_path or "")
            norm = normalize_path(combined)
            for method in c.methods:
                out.append(RouteEndpoint(
                    path=norm,
                    method=method,
                    auth_required=auth,
                    auth_info=info,
                    source_file=r.rel_path,
                    line_number=c.line_number,
                    framework=c.framework,
                ))
        return out

    # Backwards-compatible single-file entry point.
    def parse_file(self, filepath: str, rel_path: str) -> List[RouteEndpoint]:
        r = _extract_file((filepath, rel_path, self.auth_config))
        prefix_map = dict(self.prefix_map)
        prefix_map.update(r.include_prefixes)
        aliases = set(self.auth_aliases) | r.alias_names
        return self._finalize(r, prefix_map, aliases)
