import re
from collections.abc import Iterable
from typing import Any

from .models import Finding

SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token)(?:['\"])?\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
)
HTTP_SCHEMES = ("http://",)


def _operations(document: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any]]]:
    for path, item in (document.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options", "trace"} and isinstance(operation, dict):
                yield method.upper(), path, operation


def _contains_secret(value: Any) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in SECRET_PATTERNS)
    if isinstance(value, dict):
        return any(_contains_secret(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


def scan(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    servers = document.get("servers") or []
    for index, server in enumerate(servers):
        url = server.get("url", "") if isinstance(server, dict) else ""
        if isinstance(url, str) and url.lower().startswith(HTTP_SCHEMES):
            findings.append(Finding("insecure-server", "high", "Server URL uses unencrypted HTTP", f"servers[{index}].url"))

    security_schemes = (document.get("components") or {}).get("securitySchemes") or {}
    if not security_schemes:
        findings.append(Finding("missing-security-scheme", "medium", "No reusable security scheme is declared", "components.securitySchemes"))

    global_security = document.get("security")
    if global_security == []:
        findings.append(Finding("global-security-disabled", "medium", "Global security is explicitly disabled", "security"))

    paths = document.get("paths") or {}
    if not paths:
        findings.append(Finding("empty-paths", "low", "The document declares no API paths", "paths"))

    for method, path, operation in _operations(document):
        location = f"paths.{path}.{method.lower()}"
        if not operation.get("operationId"):
            findings.append(Finding("missing-operation-id", "low", "Operation has no stable operationId", location))
        if global_security is None and not operation.get("security") and security_schemes:
            findings.append(Finding("unprotected-operation", "medium", "Operation has no security requirement", location))
        declared_params = {
            parameter.get("name")
            for parameter in operation.get("parameters", [])
            if isinstance(parameter, dict) and parameter.get("in") == "path"
        }
        for parameter in (paths.get(path) or {}).get("parameters", []):
            if isinstance(parameter, dict) and parameter.get("in") == "path":
                declared_params.add(parameter.get("name"))
        for path_parameter in re.findall(r"\{([^}]+)\}", path):
            if path_parameter not in declared_params:
                findings.append(Finding("missing-path-parameter", "medium", f"Path parameter '{path_parameter}' is not declared", location))
        if _contains_secret(operation):
            findings.append(Finding("secret-in-document", "high", "Possible credential or private key found in operation data", location))

    return findings
