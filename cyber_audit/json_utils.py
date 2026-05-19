"""LLM output JSON utilities — extraction and schema validation."""

import json
import re
from typing import Any, Union


def extract_json(text: str) -> Union[dict, list, Any]:
    """Extract a JSON object or array from LLM output text.

    Handles:
    - Plain JSON objects/arrays
    - Markdown-fenced JSON (```json ... ``` or ``` ... ```)
    - JSON with leading/trailing explanatory text

    Args:
        text: Raw LLM output that may contain JSON.

    Returns:
        Parsed Python dict (or list, if the JSON is an array).

    Raises:
        ValueError: If no valid JSON object or array can be extracted.
    """
    # Strategy 1: Try parsing the entire text as JSON
    trimmed = text.strip()
    try:
        return json.loads(trimmed)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown fences ```json ... ``` or ``` ... ```
    fence_pattern = r"```(?:json)?\s*([\s\S]*?)```"
    fenced = re.findall(fence_pattern, text)
    for block in fenced:
        block = block.strip()
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            continue

    # Strategy 3: Find the first balanced JSON object or array via brace/brace
    # matching — scan for '{' or '[' then find the matching closing character.
    candidates = _find_balanced_json_candidates(text)
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    raise ValueError("No valid JSON found in text")


def _find_balanced_json_candidates(text: str):
    """Yield substrings that look like balanced JSON objects or arrays.

    Scans for opening '{' or '[' and attempts to find the matching closing
    character, accounting for strings and nested structures.
    """
    openers = {"{": "}", "[": "]"}
    for i, ch in enumerate(text):
        if ch not in openers:
            continue

        closer = openers[ch]
        depth = 0
        in_string = False
        escape = False
        start = i

        for j in range(i, len(text)):
            c = text[j]

            if escape:
                escape = False
                continue

            if c == "\\" and in_string:
                escape = True
                continue

            if c == '"':
                in_string = not in_string
                continue

            if in_string:
                continue

            if c == ch:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    yield text[start : j + 1]
                    break  # found this candidate, move to next opener
        # If we exit the loop without depth==0, it's unbalanced — skip


def validate_schema(data_dict: dict, schema_path: str) -> list[str]:
    """Validate a dictionary against a JSON Schema file.

    Args:
        data_dict: The data to validate.
        schema_path: Path to a JSON file containing the schema.

    Returns:
        List of human-readable error strings.  Empty list means valid.
    """
    import jsonschema

    with open(schema_path, "r") as f:
        schema = json.load(f)

    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(data_dict))

    # Build human-readable error messages
    messages = []
    for err in errors:
        # The JSON path (e.g. "$.name") gives context
        path = ".".join(str(p) for p in err.absolute_path) if err.absolute_path else "(root)"
        messages.append(f"{err.message} at {path}")

    return messages
