"""JSON-safe serialization for Hrz5 domain objects.

``to_jsonable(obj)`` converts dataclasses, enums, datetimes and nested containers into
plain JSON-serializable Python. Mirrors the Rsk1 ``domain/serialization.py`` rules so the
read-back JSON (``GET /v1/audit``) is byte-compatible with what Rsk1 originally sent:

* ``enum.Enum``  -> ``.value``
* ``datetime``   -> ``.isoformat()``
* dataclass      -> ``{field: to_jsonable(value)}`` (recursively)
* tuple / list   -> ``[to_jsonable(x), ...]`` (tuples become lists for JSON)
* dict           -> ``{str(key): to_jsonable(v)}``

Pure standard library; no Google Cloud imports.
"""

from __future__ import annotations

import dataclasses
import enum
from datetime import date, datetime
from typing import Any


def to_jsonable(obj: Any) -> Any:
    """Recursively convert ``obj`` into JSON-serializable Python.

    Unknown objects fall back to ``str(obj)`` so serialization never raises at an
    audit/serialization boundary.
    """
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, enum.Enum):
        return to_jsonable(obj.value)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", errors="replace")
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(x) for x in obj]
    return str(obj)
