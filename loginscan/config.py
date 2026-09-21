"""Load a scan profile from a JSON (always) or YAML (if pyyaml is installed) file."""
from __future__ import annotations

import json
from typing import Any, Dict


class ConfigError(Exception):
    pass


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # optional
        except ImportError as e:
            raise ConfigError("YAML config needs pyyaml (pip install pyyaml) or use JSON.") from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError("Config must be a mapping/object.")
    return data
