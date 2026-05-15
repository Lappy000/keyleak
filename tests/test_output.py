"""Tests for keyleak.output — rendering functions."""

import io
import json

from rich.console import Console

from keyleak.output import render_compact, render_json, render_table
from keyleak.validators import KeyStatus, ValidationResult


def _make_result(service="github", status=KeyStatus.VALID, message="OK"):
    return ValidationResult(
        key_value="test_key_value_12345",
        service=service,
        status=status,
        message=message,
        http_status=200,
        response_time_ms=50.0,
    )


class TestRenderJson:
    """Test JSON output rendering."""

    def test_outputs_valid_json(self):
        results = [_make_result()]
        buf = io.StringIO()
        render_json(results, output=buf)
        buf.seek(0)
        data = json.loads(buf.read())
        assert isinstance(data, dict)
        assert "results" in data
        assert "summary" in data
        assert len(data["results"]) == 1
        assert data["results"][0]["service"] == "github"
        assert data["results"][0]["status"] == "valid"
        assert data["summary"]["total"] == 1
        assert data["summary"]["valid"] == 1

    def test_empty_results_outputs_empty_dict(self):
        buf = io.StringIO()
        render_json([], output=buf)
        buf.seek(0)
        data = json.loads(buf.read())
        assert data["results"] == []
        assert data["summary"]["total"] == 0


class TestRenderCompact:
    """Test compact output rendering."""

    def test_compact_produces_output(self):
        results = [_make_result(), _make_result(service="aws", status=KeyStatus.INVALID)]
        console = Console(file=io.StringIO(), force_terminal=False)
        render_compact(results, console=console)
        output = console.file.getvalue()
        assert len(output) > 0


class TestRenderTable:
    """Test rich table rendering."""

    def test_table_produces_output(self):
        results = [_make_result()]
        console = Console(file=io.StringIO(), force_terminal=False)
        render_table(results, console=console)
        output = console.file.getvalue()
        assert "github" in output.lower() or len(output) > 0
