from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PRIVATE_FIELDS = {"author", "authors", "contact", "email"}


def remove_personal_metadata(value: Any) -> None:
    if isinstance(value, dict):
        for key in list(value):
            if key.casefold() in PRIVATE_FIELDS:
                del value[key]
            else:
                remove_personal_metadata(value[key])
    elif isinstance(value, list):
        for item in value:
            remove_personal_metadata(item)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: sanitize_sbom.py <cyclonedx-json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
            raise ValueError("expected a CycloneDX JSON document")
        remove_personal_metadata(document)
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"could not sanitize CycloneDX metadata: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
