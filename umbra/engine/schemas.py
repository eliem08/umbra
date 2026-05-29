from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

# Canonical display names for frameworks we know how to parse. Anything else is
# accepted as-is (title-cased) so new language parsers can register their own
# framework label without touching this validator.
KNOWN_FRAMEWORKS = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "spring": "Spring",
    "spring boot": "Spring Boot",
    "springboot": "Spring Boot",
    "express": "Express",
}

# Maps a framework to the language it belongs to. Used when a parser does not
# set `language` explicitly.
FRAMEWORK_LANGUAGE = {
    "FastAPI": "python",
    "Flask": "python",
    "Spring": "java",
    "Spring Boot": "java",
    "Express": "javascript",
}


class RouteEndpoint(BaseModel):
    """
    Represents an API route endpoint identified during static analysis.
    """
    path: str = Field(description="The normalized path pattern of the route (e.g., /users/:id)")
    method: str = Field(description="The HTTP method of the route (e.g., GET, POST)")
    auth_required: bool = Field(default=False, description="Whether authorization middleware/dependency is attached")
    auth_info: Optional[str] = Field(default=None, description="Details of the identified auth mechanism (e.g., Depends(verify_token))")
    source_file: str = Field(description="The relative path to the source file")
    line_number: int = Field(description="The 1-indexed line number in the source file where the route was defined")
    framework: str = Field(description="The target web framework (e.g. 'FastAPI', 'Flask', 'Spring Boot', 'Express')")
    language: Optional[str] = Field(default=None, description="The source language: 'python', 'java', or 'javascript'")

    # --- Git provenance (populated only when a git baseline is supplied) ---
    is_new: bool = Field(default=False, description="True if this endpoint was introduced/changed within the inspected git window")
    change_type: Optional[str] = Field(default=None, description="'added' or 'modified' when git attribution is available")
    commit: Optional[str] = Field(default=None, description="Short SHA of the commit that introduced/last touched this endpoint")
    author: Optional[str] = Field(default=None, description="Author of the introducing/modifying commit")
    committed_at: Optional[str] = Field(default=None, description="ISO timestamp of the introducing/modifying commit")

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        """Ensure HTTP method is always in uppercase."""
        return v.upper()

    @field_validator("framework")
    @classmethod
    def validate_framework(cls, v: str) -> str:
        """Normalize known frameworks to their canonical display name; accept others as-is."""
        key = v.strip().lower()
        if key in KNOWN_FRAMEWORKS:
            return KNOWN_FRAMEWORKS[key]
        if not v.strip():
            raise ValueError("Framework must be a non-empty string")
        return v.strip()

    def model_post_init(self, __context) -> None:
        # Infer language from the framework when a parser did not set it explicitly.
        if self.language is None:
            self.language = FRAMEWORK_LANGUAGE.get(self.framework)


class ScanResult(BaseModel):
    """
    Represents the output of the codebase parser(s).
    """
    routes: List[RouteEndpoint] = Field(default_factory=list, description="List of endpoints parsed from the target source files")


class OpenAPIMatch(BaseModel):
    """
    Represents a comparison result of a codebase endpoint against the OpenAPI registry.
    """
    route: RouteEndpoint = Field(description="The codebase endpoint being evaluated")
    registered: bool = Field(description="True if this route matches an endpoint in openapi.json")
    status: str = Field(description="Matching status: 'documented', 'shadow' (not in openapi.json), or 'missing_auth'")


class ScannerReport(BaseModel):
    """
    The final DevSecOps posture report indicating coverage and vulnerabilities.
    """
    parsed_routes_count: int = Field(description="Total count of routes parsed from codebase")
    registered_routes_count: int = Field(description="Total count of routes declared in the OpenAPI spec")
    shadow_endpoints: List[RouteEndpoint] = Field(default_factory=list, description="Endpoints in code that are missing from the OpenAPI registry")
    missing_auth_endpoints: List[RouteEndpoint] = Field(default_factory=list, description="Endpoints lacking any authorization checks")
    new_endpoints: List[RouteEndpoint] = Field(default_factory=list, description="Endpoints introduced/changed within the inspected git window")
    coverage_ratio: float = Field(description="The OpenAPI documentation path coverage ratio (between 0.0 and 1.0)")
