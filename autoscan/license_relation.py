"""Classify multi-license semantics for report output."""

from __future__ import annotations

import re

_UNKNOWN_LICENSES = {
    "",
    "-",
    "UNKNOWN",
    "NOASSERTION",
    "NONE",
    "N/A",
    "NULL",
    "LicenseRef-No-Declared-License",
}

_TOKEN_RE = re.compile(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9][A-Za-z0-9.+-]*")
_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def classify_license_relation(license_names: list[str] | tuple[str, ...] | set[str]) -> dict[str, str | bool]:
    names = [str(name or "").strip() for name in license_names if str(name or "").strip()]
    unique_names = list(dict.fromkeys(names))

    if not unique_names:
        return _review("No license declaration found.")

    if any(_is_unknown_or_custom(name) for name in unique_names):
        return _review("Unknown, custom, or non-standard license identifier requires manual review.")

    if len(unique_names) > 1:
        return _review("Multiple license rows do not prove whether obligations are OR or AND.")

    expression = unique_names[0]
    parse = _parse_spdx_expression(expression)
    if not parse["valid"]:
        return _review("License expression is not clearly valid SPDX.")

    has_or = bool(parse["has_or"])
    has_and = bool(parse["has_and"])
    if has_or and has_and:
        return _review("Expression mixes AND and OR; manual legal review is required.")
    if has_or:
        return {
            "relation": "OR",
            "requirement": "User may choose one listed license to comply with.",
            "reason": "Valid SPDX OR expression.",
            "is_spdx_expression": True,
        }
    return {
        "relation": "AND",
        "requirement": "User must comply with all listed license obligations.",
        "reason": "Valid SPDX license or AND expression.",
        "is_spdx_expression": has_and,
    }


def _review(reason: str) -> dict[str, str | bool]:
    return {
        "relation": "REVIEW",
        "requirement": "Manual review required.",
        "reason": reason,
        "is_spdx_expression": False,
    }


def _is_unknown_or_custom(name: str) -> bool:
    if name in _UNKNOWN_LICENSES or name.upper() in _UNKNOWN_LICENSES:
        return True
    if name.startswith("LicenseRef-"):
        return True
    return False


def _parse_spdx_expression(expression: str) -> dict[str, bool]:
    tokens = _TOKEN_RE.findall(expression)
    if not tokens or "".join(tokens) == "":
        return {"valid": False, "has_or": False, "has_and": False}

    compact_original = re.sub(r"\s+", "", expression)
    compact_tokens = "".join(tokens)
    if compact_original != compact_tokens:
        return {"valid": False, "has_or": False, "has_and": False}

    has_or = "OR" in tokens
    has_and = "AND" in tokens
    expect_license = True
    paren_balance = 0
    previous_was_with = False

    for token in tokens:
        if token == "(":
            if not expect_license:
                return {"valid": False, "has_or": has_or, "has_and": has_and}
            paren_balance += 1
            continue
        if token == ")":
            if expect_license or previous_was_with:
                return {"valid": False, "has_or": has_or, "has_and": has_and}
            paren_balance -= 1
            if paren_balance < 0:
                return {"valid": False, "has_or": has_or, "has_and": has_and}
            continue
        if token in {"AND", "OR"}:
            if expect_license or previous_was_with:
                return {"valid": False, "has_or": has_or, "has_and": has_and}
            expect_license = True
            previous_was_with = False
            continue
        if token == "WITH":
            if expect_license or previous_was_with:
                return {"valid": False, "has_or": has_or, "has_and": has_and}
            expect_license = True
            previous_was_with = True
            continue
        if not expect_license:
            return {"valid": False, "has_or": has_or, "has_and": has_and}
        if not _SPDX_ID_RE.match(token) or token.startswith("LicenseRef-"):
            return {"valid": False, "has_or": has_or, "has_and": has_and}
        expect_license = False
        previous_was_with = False

    return {"valid": not expect_license and paren_balance == 0, "has_or": has_or, "has_and": has_and}
