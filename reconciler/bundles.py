"""Translate between the YAML files in this repo and API bundle payloads.

The on-disk YAML is the desired state; these helpers strip the output-only
fields the API returns on reads (``deployment_slug``, ``product``) so a
file written by ``export`` round-trips cleanly through ``apply``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"

DETECTION_CODE_FILE = POLICIES_DIR / "detection-code.yaml"
DETECTION_SECRETS_FILE = POLICIES_DIR / "detection-secrets.yaml"
REMEDIATION_FILE = POLICIES_DIR / "remediation.yaml"

# Fields the API returns on reads but ignores in request bodies. Dropping
# them keeps the YAML free of values a customer should not hand-edit.
_DETECTION_OUTPUT_ONLY = ("deployment_slug", "product")
_REMEDIATION_OUTPUT_ONLY = ("deployment_slug",)


def detection_to_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "rulesets": raw.get("rulesets", []),
        "rules": raw.get("rules", []),
        "disabled": raw.get("disabled", []),
        "exceptions": raw.get("exceptions", []),
    }


def remediation_to_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    return {"policies": raw.get("policies", [])}


def write_yaml(path: Path, bundle: dict[str, Any], drop: tuple[str, ...]) -> None:
    cleaned = {key: value for key, value in bundle.items() if key not in drop}
    path.write_text(
        yaml.safe_dump(cleaned, sort_keys=False, default_flow_style=False)
    )


def write_detection_yaml(path: Path, bundle: dict[str, Any]) -> None:
    write_yaml(path, bundle, _DETECTION_OUTPUT_ONLY)


def write_remediation_yaml(path: Path, bundle: dict[str, Any]) -> None:
    write_yaml(path, bundle, _REMEDIATION_OUTPUT_ONLY)


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}
