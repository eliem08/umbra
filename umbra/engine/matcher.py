import re
import json
import os
import httpx
from typing import List, Union, Dict, Any, Set, Tuple
from .schemas import RouteEndpoint, OpenAPIMatch, ScannerReport, ScanResult
from .parser import normalize_path

class OpenAPIMatcher:
    """
    Compares AST parsed endpoints against an OpenAPI spec registry to identify
    shadow APIs and endpoints missing authentication.
    """
    def __init__(self, openapi_data: Union[str, Dict[str, Any]]):
        self.openapi_dict = self._load_openapi(openapi_data)
        self.registered_endpoints = self._parse_registered_endpoints()
        # Pre-calculate shapes for parameter-agnostic matching
        self.registered_shapes = {
            (self._normalize_for_matching(path), method) for path, method in self.registered_endpoints
        }

    def _normalize_for_matching(self, path: str) -> str:
        """Helper to convert parameter names to generic placeholders."""
        path = normalize_path(path)
        return re.sub(r":\w+", r":{}", path)

    def _load_openapi(self, openapi_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Loads the OpenAPI dictionary from a file path, raw JSON string, HTTP(S) URL, or a dictionary.
        """
        if isinstance(openapi_data, dict):
            return openapi_data
        
        if not isinstance(openapi_data, str):
            raise ValueError("openapi_data must be a string or a dictionary.")
            
        data_str = openapi_data.strip()
        
        # 1. Handle URL
        if data_str.startswith("http://") or data_str.startswith("https://"):
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.get(data_str)
                    resp.raise_for_status()
                    return resp.json()
            except Exception as e:
                raise ValueError(f"Failed to fetch OpenAPI spec from URL {data_str}: {e}")
        
        # 2. Handle local file path
        if os.path.exists(data_str):
            try:
                with open(data_str, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                raise ValueError(f"Failed to parse OpenAPI JSON file {data_str}: {e}")
                
        # 3. Handle raw JSON content string
        try:
            return json.loads(data_str)
        except Exception as e:
            raise ValueError(f"openapi_data is not a valid file path, URL, or JSON: {e}")

    def _parse_registered_endpoints(self) -> Set[Tuple[str, str]]:
        """
        Traverses the paths object of the OpenAPI schema to extract registered endpoints
        as normalized (path, method) tuples.
        """
        endpoints: Set[Tuple[str, str]] = set()
        paths = self.openapi_dict.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints
            
        for path_key, path_item in paths.items():
            normalized = normalize_path(path_key)
            if not isinstance(path_item, dict):
                continue
            for method_key in path_item.keys():
                if method_key.lower() in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    endpoints.add((normalized, method_key.upper()))
        return endpoints

    def match_endpoints(self, scan_result: ScanResult) -> List[OpenAPIMatch]:
        """
        Evaluates each parsed endpoint in the scan result against the registered OpenAPI paths.
        """
        matches: List[OpenAPIMatch] = []
        for route in scan_result.routes:
            normalized_route_path = normalize_path(route.path)
            
            # 1. Exact match (parameter names identical)
            is_registered = (normalized_route_path, route.method) in self.registered_endpoints
            
            # 2. Parameter-agnostic shape-based match fallback
            if not is_registered:
                route_shape = self._normalize_for_matching(normalized_route_path)
                is_registered = (route_shape, route.method) in self.registered_shapes
                
            if not is_registered:
                status = "shadow"
            elif not route.auth_required:
                status = "missing_auth"
            else:
                status = "documented"
                
            matches.append(OpenAPIMatch(route=route, registered=is_registered, status=status))
        return matches

    def generate_report(self, scan_result: ScanResult) -> ScannerReport:
        """
        Generates a final ScannerReport containing stats, shadow APIs, missing auths,
        and the documentation coverage ratio.
        """
        matches = self.match_endpoints(scan_result)
        
        shadow_endpoints: List[RouteEndpoint] = []
        missing_auth_endpoints: List[RouteEndpoint] = []
        
        # Calculate unique sets of endpoints to accurately compute coverage
        parsed_set: Set[Tuple[str, str]] = set()
        for route in scan_result.routes:
            parsed_set.add((normalize_path(route.path), route.method))
            
        # Count unique codebase endpoints registered (handling name-varied parameters)
        intersection_count = 0
        for path, method in parsed_set:
            if (path, method) in self.registered_endpoints:
                intersection_count += 1
            else:
                shape = self._normalize_for_matching(path)
                if (shape, method) in self.registered_shapes:
                    intersection_count += 1
        
        # Coverage ratio C
        if len(parsed_set) == 0:
            coverage_ratio = 1.0
        else:
            coverage_ratio = intersection_count / len(parsed_set)
            
        new_endpoints: List[RouteEndpoint] = []
        for match in matches:
            if match.status == "shadow":
                shadow_endpoints.append(match.route)
            if not match.route.auth_required:
                missing_auth_endpoints.append(match.route)
            if match.route.is_new:
                new_endpoints.append(match.route)

        return ScannerReport(
            parsed_routes_count=len(scan_result.routes),
            registered_routes_count=len(self.registered_endpoints),
            shadow_endpoints=shadow_endpoints,
            missing_auth_endpoints=missing_auth_endpoints,
            new_endpoints=new_endpoints,
            coverage_ratio=coverage_ratio
        )
