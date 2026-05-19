"""Tests for cyber_audit.json_utils — extract_json and validate_schema."""

import json
import pytest
from cyber_audit.json_utils import extract_json, validate_schema


# ---------------------------------------------------------------------------
# extract_json
# ---------------------------------------------------------------------------

class TestExtractJson:
    """Tests for extract_json(text) -> dict."""

    def test_clean_json_object(self):
        """Plain JSON object — parsed directly."""
        text = '{"name": "Alice", "age": 30}'
        result = extract_json(text)
        assert result == {"name": "Alice", "age": 30}

    def test_clean_json_array(self):
        """Plain JSON array — parsed directly."""
        text = '[{"id": 1}, {"id": 2}]'
        result = extract_json(text)
        assert result == [{"id": 1}, {"id": 2}]

    def test_markdown_fenced_json(self):
        """JSON wrapped in ```json ... ``` fences."""
        text = '```json\n{"key": "value"}\n```'
        result = extract_json(text)
        assert result == {"key": "value"}

    def test_markdown_fenced_no_lang(self):
        """JSON wrapped in plain ``` ... ``` fences (no language tag)."""
        text = '```\n{"status": "ok"}\n```'
        result = extract_json(text)
        assert result == {"status": "ok"}

    def test_json_with_trailing_text(self):
        """JSON object followed by explanatory text."""
        text = 'The result is: {"score": 95}\nAnd that concludes the analysis.'
        result = extract_json(text)
        assert result == {"score": 95}

    def test_json_with_leading_text(self):
        """Explanatory text before a JSON object."""
        text = 'Here is the output:\n{"valid": true}'
        result = extract_json(text)
        assert result == {"valid": True}

    def test_no_json_raises_value_error(self):
        """Text with no JSON at all raises ValueError."""
        with pytest.raises(ValueError, match="No valid JSON found"):
            extract_json("This is just plain text.")

    def test_malformed_json_raises_value_error(self):
        """Malformed JSON-like text raises ValueError."""
        with pytest.raises(ValueError, match="No valid JSON found"):
            extract_json('{"broken": ')

    def test_nested_json_object(self):
        """Complex nested JSON object."""
        text = '{"user": {"name": "Bob", "scores": [85, 92]}}'
        result = extract_json(text)
        assert result == {"user": {"name": "Bob", "scores": [85, 92]}}

    def test_whitespace_only_json(self):
        """JSON with surrounding whitespace."""
        text = '\n  \t  {"x": 1}  \n'
        result = extract_json(text)
        assert result == {"x": 1}


# ---------------------------------------------------------------------------
# validate_schema
# ---------------------------------------------------------------------------

class TestValidateSchema:
    """Tests for validate_schema(data_dict, schema_path) -> list[str]."""

    SCHEMA = {
        "type": "object",
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
        },
        "additionalProperties": False,
    }

    @pytest.fixture
    def schema_file(self, tmp_path):
        """Write the test schema to a temporary file, return its path."""
        schema_path = tmp_path / "test_schema.json"
        schema_path.write_text(json.dumps(self.SCHEMA))
        return str(schema_path)

    def test_valid_data(self, schema_file):
        """Valid data returns empty error list."""
        data = {"id": 1, "name": "Alice"}
        errors = validate_schema(data, schema_file)
        assert errors == []

    def test_missing_required_field(self, schema_file):
        """Missing 'name' returns an error mentioning the field."""
        data = {"id": 42}
        errors = validate_schema(data, schema_file)
        assert len(errors) > 0
        assert any("required" in e.lower() or "name" in e.lower() for e in errors)

    def test_wrong_type(self, schema_file):
        """Wrong type for 'id' returns an error."""
        data = {"id": "not-a-number", "name": "Bob"}
        errors = validate_schema(data, schema_file)
        assert len(errors) > 0
        assert any("type" in e.lower() or "integer" in e.lower() for e in errors)

    def test_additional_properties_disallowed(self, schema_file):
        """Extra properties when additionalProperties=False."""
        data = {"id": 3, "name": "Carol", "extra_field": "nope"}
        errors = validate_schema(data, schema_file)
        assert len(errors) > 0
        assert any(
            "additional" in e.lower() or "extra" in e.lower() for e in errors
        )

    def test_multiple_errors(self, schema_file):
        """Multiple violations produce multiple error strings."""
        data = {"id": "wrong", "extra": True}  # missing name, wrong id type, extra property
        errors = validate_schema(data, schema_file)
        assert len(errors) >= 2  # at least two violations

    def test_empty_object_against_non_empty_required(self, schema_file):
        """Empty object when schema requires fields."""
        data = {}
        errors = validate_schema(data, schema_file)
        assert len(errors) > 0
