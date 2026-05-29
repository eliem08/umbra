import ast
import os
import re
from typing import List, Tuple, Optional, Set
from .schemas import RouteEndpoint, ScanResult
from .authconfig import AuthConfig
from .fsutil import iter_source_files, DEFAULT_EXCLUDE_DIRS

# Common HTTP methods to match in decorators
HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "route", "api_route"}
# Default auth keywords, retained for backwards compatibility. Detection is now
# driven by AuthConfig; this constant mirrors the AuthConfig defaults.
AUTH_KEYWORDS = AuthConfig().keywords

def normalize_path(path: str) -> str:
    """
    Standardizes endpoint paths to a canonical colon-prefixed format (e.g., /users/:id).
    Removes trailing slashes (except root).
    """
    if not path:
        return "/"
    
    # Strip trailing slash unless path is just "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
        
    # Ensure it starts with "/"
    if not path.startswith("/"):
        path = "/" + path

    # 1. Normalize Flask-style path parameters: <[type:]name> -> :name
    # e.g., <int:user_id> -> :user_id, <username> -> :username
    path = re.sub(r"<(?:\w+:)?(\w+)>", r":\1", path)

    # 2. Normalize FastAPI-style path parameters: {name} -> :name
    # e.g., {user_id} -> :user_id
    path = re.sub(r"\{(\w+)\}", r":\1", path)

    return path


class ASTParser:
    """
    Static analysis parser that uses Python's native AST module to detect route endpoints
    and authentication controls in FastAPI and Flask codebases.
    """
    def __init__(self, base_dir: str, auth_config: Optional[AuthConfig] = None,
                 exclude_dirs: Optional[Set[str]] = None):
        self.base_dir = os.path.abspath(base_dir)
        self.prefix_map = {}
        self.auth_aliases: Set[str] = set()
        self.auth_config = auth_config or AuthConfig()
        self.exclude_dirs = DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs

    def parse_directory(self) -> ScanResult:
        """
        Recursively searches the base directory and parses all Python files.
        """
        self.prefix_map, self.auth_aliases = self.pre_scan()
        endpoints: List[RouteEndpoint] = []
        for full_path, rel_path in iter_source_files(self.base_dir, (".py",), self.exclude_dirs):
            endpoints.extend(self.parse_file(full_path, rel_path))
        return ScanResult(routes=endpoints)

    def pre_scan(self) -> Tuple[dict, Set[str]]:
        """
        Scans the tree for cross-file signals:
          - APIRouter/Blueprint `prefix=`/`url_prefix=` on include_router/register_blueprint
          - module-level `NAME = Annotated[..., Depends(auth_callable)]` / `NAME = Depends(...)`
            auth-dependency aliases (e.g. FastAPI's `CurrentUser`), so a parameter merely
            *annotated* with that alias is recognized as authenticated.
        """
        prefix_map: dict = {}
        auth_aliases: Set[str] = set()

        for full_path, _ in iter_source_files(self.base_dir, (".py",), self.exclude_dirs):
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    source = f.read()
                tree = ast.parse(source, filename=full_path)
            except Exception:
                continue

            for node in ast.walk(tree):
                # include_router / register_blueprint prefixes
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr in ("register_blueprint", "include_router"):
                        if node.args:
                            var_name = self._get_name_str(node.args[0])
                            if var_name:
                                prefix_kw = "prefix" if func.attr == "include_router" else "url_prefix"
                                for kw in node.keywords:
                                    if kw.arg == prefix_kw and isinstance(kw.value, ast.Constant):
                                        prefix_map[var_name] = str(kw.value.value)
                                        break
                # Auth-dependency aliases: NAME = Annotated[...] / Depends(...) / Security(...)
                elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target = node.targets[0]
                    if isinstance(target, ast.Name):
                        try:
                            rhs = ast.unparse(node.value)
                        except Exception:
                            continue
                        if self.auth_config.python_auth_expr_match(rhs):
                            auth_aliases.add(target.id)

        return prefix_map, auth_aliases

    def _local_constructor_prefixes(self, tree: ast.AST) -> dict:
        """
        Detect file-local router/blueprint prefixes declared on the constructor, e.g.
        `router = APIRouter(prefix="/items")` or `bp = Blueprint(..., url_prefix="/x")`.
        Kept file-local because the variable name (often just `router`) collides across files.
        """
        local: dict = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Call):
                    ctor = self._get_name_str(node.value.func) or ""
                    if ctor.endswith("APIRouter") or ctor.endswith("Blueprint"):
                        for kw in node.value.keywords:
                            if kw.arg in ("prefix", "url_prefix") and isinstance(kw.value, ast.Constant):
                                local[node.targets[0].id] = str(kw.value.value)
        return local

    def parse_file(self, filepath: str, rel_path: str) -> List[RouteEndpoint]:
        """
        Parses a single Python source file and extracts route endpoints.
        """
        endpoints: List[RouteEndpoint] = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
        except Exception:
            # Silently skip unparseable files (e.g. syntax errors or empty files)
            return []

        # Gather information about imports to help classify framework
        has_flask_import = False
        has_fastapi_import = False
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    if "flask" in name.name:
                        has_flask_import = True
                    if "fastapi" in name.name:
                        has_fastapi_import = True
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    if "flask" in node.module:
                        has_flask_import = True
                    if "fastapi" in node.module:
                        has_fastapi_import = True

        # File-local router/blueprint constructor prefixes (e.g. APIRouter(prefix="/items")).
        local_prefixes = self._local_constructor_prefixes(tree)

        # Search for function and class method definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.decorator_list:
                    continue

                # Scan decorators to identify if this function is a route handler
                route_decorators: List[Tuple[ast.AST, str, str, str]] = [] # (decorator, caller, attribute/name, path)
                auth_decorators: List[str] = []

                for dec in node.decorator_list:
                    caller, attr, path = self._parse_decorator(dec)
                    if attr and attr.lower() in HTTP_METHODS:
                        if path is not None:
                            route_decorators.append((dec, caller or "", attr, path))
                    elif attr:
                        # Non-route decorator, check if it contains auth keywords (Flask-style auth decorator)
                        if self.auth_config.keyword_match(attr):
                            auth_decorators.append(attr)
                    elif isinstance(dec, ast.Name):
                        if self.auth_config.keyword_match(dec.id):
                            auth_decorators.append(dec.id)

                if not route_decorators:
                    continue

                # Determine framework heuristic for this function
                # Defaults to FastAPI if not explicitly Flask-like
                framework = "FastAPI"
                if has_flask_import and not has_fastapi_import:
                    framework = "Flask"
                else:
                    # Look at route decorator caller names or auth decorators
                    for _, caller, attr, _ in route_decorators:
                        if "bp" in caller.lower() or "blueprint" in caller.lower():
                            framework = "Flask"
                            break
                        if attr == "route" and not has_fastapi_import:
                            # Flask typically uses @app.route; FastAPI typically uses @app.get, etc.
                            framework = "Flask"

                # Detect authorization in the function signature. Modern FastAPI puts
                # the dependency in the parameter *annotation* via `Annotated[...,
                # Depends(...)]` (often behind an alias like `CurrentUser`), while older
                # style uses parameter *defaults*. We inspect both, and only count
                # dependencies whose callable looks auth-related (not e.g. Depends(get_db)).
                sig_auth_info: Optional[str] = None
                sig_auth_required = False

                all_args = list(node.args.args) + list(node.args.posonlyargs) + list(node.args.kwonlyargs)
                for arg in all_args:
                    if arg.annotation is not None:
                        try:
                            ann = ast.unparse(arg.annotation)
                        except Exception:
                            ann = ""
                        if self.auth_config.python_auth_expr_match(ann, self.auth_aliases):
                            sig_auth_required = True
                            sig_auth_info = f"Argument {arg.arg} annotation: {ann}"
                            break

                if not sig_auth_required:
                    # Parameter defaults (positional + keyword-only).
                    pos_args = node.args.args
                    defaults = node.args.defaults
                    offset = len(pos_args) - len(defaults)
                    default_pairs = [(pos_args[offset + i].arg, d) for i, d in enumerate(defaults)]
                    default_pairs += [(a.arg, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d]
                    for arg_name, default_val in default_pairs:
                        unparsed_val = ast.unparse(default_val)
                        if self.auth_config.python_auth_expr_match(unparsed_val, self.auth_aliases):
                            sig_auth_required = True
                            sig_auth_info = f"Argument {arg_name} default: {unparsed_val}"
                            break

                # Build route endpoints for each route decorator
                for dec, caller, attr, path in route_decorators:
                    # Compose prefixes: an include_router/register_blueprint prefix (global,
                    # by caller name) plus a constructor prefix (file-local). Either may be "".
                    include_prefix = self.prefix_map.get(caller, "")
                    ctor_prefix = local_prefixes.get(caller, "")
                    combined_path = include_prefix + ctor_prefix + path
                    
                    # Normalize the path
                    norm_path = normalize_path(combined_path)
                    
                    # Extract HTTP methods from decorator
                    methods = self._extract_methods(dec, attr)
                    
                    # Check for route-level dependency parameters in FastAPI decorator (dependencies=[Depends(...)])
                    dec_auth_required = False
                    dec_auth_info: Optional[str] = None
                    if isinstance(dec, ast.Call):
                        for kw in dec.keywords:
                            if kw.arg == "dependencies":
                                unparsed_kw = ast.unparse(kw.value)
                                if self.auth_config.python_auth_expr_match(unparsed_kw, self.auth_aliases):
                                    dec_auth_required = True
                                    dec_auth_info = f"Decorator dependencies: {unparsed_kw}"

                    # Determine ultimate auth status
                    auth_required = sig_auth_required or dec_auth_required or len(auth_decorators) > 0
                    
                    # Build auth info string
                    info_parts = []
                    if sig_auth_info:
                        info_parts.append(sig_auth_info)
                    if dec_auth_info:
                        info_parts.append(dec_auth_info)
                    if auth_decorators:
                        info_parts.append(f"Flask Decorators: {', '.join(auth_decorators)}")
                    auth_info = "; ".join(info_parts) if info_parts else None

                    # If multiple methods are defined, generate an endpoint for each
                    for method in methods:
                        endpoints.append(
                            RouteEndpoint(
                                path=norm_path,
                                method=method,
                                auth_required=auth_required,
                                auth_info=auth_info,
                                source_file=rel_path,
                                line_number=node.lineno,
                                framework=framework
                            )
                        )
        return endpoints

    def _parse_decorator(self, decorator: ast.AST) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parses a decorator node and extracts:
        (caller_name, decorator_attribute_name, path_argument)
        For example: @app.get("/users") -> ("app", "get", "/users")
        """
        func = decorator.func if isinstance(decorator, ast.Call) else decorator
        
        caller = None
        attr = None
        path = None

        if isinstance(func, ast.Attribute):
            caller = self._get_name_str(func.value)
            attr = func.attr
        elif isinstance(func, ast.Name):
            attr = func.id

        # Extract path if it is a call
        if isinstance(decorator, ast.Call):
            if decorator.args:
                first_arg = decorator.args[0]
                if isinstance(first_arg, ast.Constant):
                    path = str(first_arg.value)
            else:
                for kw in decorator.keywords:
                    if kw.arg in ("path", "rule"):
                        if isinstance(kw.value, ast.Constant):
                            path = str(kw.value.value)

        return caller, attr, path

    def _get_name_str(self, node: ast.AST) -> Optional[str]:
        """Helper to get string representation of AST Names and Attributes."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_name_str(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return None

    def _extract_methods(self, decorator: ast.AST, attr: str) -> List[str]:
        """
        Extracts HTTP methods from a route decorator based on decorator verb or arguments.
        """
        # Verb-based FastAPI decorators: e.g. @app.get() -> GET
        if attr.lower() in {"get", "post", "put", "delete", "patch", "options", "head"}:
            return [attr.upper()]

        # Generic route decorators: e.g. @app.route() or @app.api_route()
        if isinstance(decorator, ast.Call):
            for kw in decorator.keywords:
                if kw.arg == "methods":
                    val = kw.value
                    if isinstance(val, ast.List):
                        return [str(el.value).upper() for el in val.elts if isinstance(el, ast.Constant)]
                    elif isinstance(val, ast.Set):
                        return [str(el.value).upper() for el in val.elts if isinstance(el, ast.Constant)]
                    elif isinstance(val, ast.Tuple):
                        return [str(el.value).upper() for el in val.elts if isinstance(el, ast.Constant)]
                    elif isinstance(val, ast.Constant):
                        return [str(val.value).upper()]
        
        # Default to GET if methods is unspecified
        return ["GET"]
