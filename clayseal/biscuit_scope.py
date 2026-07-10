"""Biscuit path-pattern scope helpers (SM-7).

Dynamic L2 file scope is encoded as ``allowed_path`` / ``denied_path`` facts on
attenuated Biscuit tokens. Fact extraction (Biscuit-specific) lives here; the
matching semantics live in ``clayseal._core`` (kept behaviorally identical to
the upper layers' implementation), re-exported for callers of this module.
Datalog still gates the coarse ``(resource, action)`` capability.
"""

from __future__ import annotations

import re
from typing import Any

from clayseal._core import evaluate_path_scope, path_matches_any

FILE_RESOURCE = "file"

__all__ = [
    "FILE_RESOURCE",
    "path_patterns_from_biscuit_blocks",
    "path_matches_any",
    "evaluate_path_scope",
]

_ALLOWED_PATH_RE = re.compile(r'allowed_path\("([^"]+)"\)')
_DENIED_PATH_RE = re.compile(r'denied_path\("([^"]+)"\)')


def path_patterns_from_biscuit_blocks(token: Any) -> tuple[list[str], list[str]]:
    """Extract path patterns from all Biscuit block sources (authority + caveats)."""
    allowed: list[str] = []
    denied: list[str] = []
    block_count_attr = getattr(token, "block_count", 0)
    block_count = int(block_count_attr() if callable(block_count_attr) else block_count_attr)
    for index in range(block_count):
        source = str(token.block_source(index))
        allowed.extend(_ALLOWED_PATH_RE.findall(source))
        denied.extend(_DENIED_PATH_RE.findall(source))
    return list(dict.fromkeys(allowed)), list(dict.fromkeys(denied))
