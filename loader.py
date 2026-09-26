import json
from pathlib import Path
from typing import Any

import yaml


def load_document(path: str | Path) -> dict[str, Any]:
    """Load a JSON or YAML OpenAPI document and validate its top-level shape."""
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8")) if source.suffix.lower() == ".json" else yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Could not read {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("The OpenAPI document must be a mapping/object")
    if data.get("openapi", "").split(".")[0:1] != ["3"]:
        raise ValueError("Only OpenAPI 3.x documents are supported")
    return data
