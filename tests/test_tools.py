"""TDD tests for cyber_audit.tools — ToolsSession + four async tool functions."""

import os
import stat
import tempfile
from pathlib import Path

import pytest

# We'll import after writing the module; for now we define the expected interface.
# Once cyber_audit/tools.py exists, we switch to real imports.
try:
    from cyber_audit.tools import ToolsSession
except ImportError:
    ToolsSession = None  # pre-module guard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_repo():
    """Create a temp directory with a few files, return its Path."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # Text files
        (root / "a.txt").write_text("alpha\nbeta\ngamma\ndelta\nepsilon\n")
        (root / "sub").mkdir()
        (root / "sub" / "b.txt").write_text("hello world\nfoo bar\n")
        (root / "sub" / "c.log").write_text("ERROR: something\nINFO: all good\nERROR: again\n")
        (root / "empty.txt").write_text("")

        yield root


@pytest.fixture
def session(tmp_repo):
    """Return a ToolsSession bound to tmp_repo."""
    from cyber_audit.tools import ToolsSession
    return ToolsSession(str(tmp_repo))


# ---------------------------------------------------------------------------
# tool_read
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_existing_file(session):
    """Read an existing text file — must return content + total_lines."""
    result = await session.tool_read("a.txt")
    assert result["content"] == "alpha\nbeta\ngamma\ndelta\nepsilon\n"
    assert result["total_lines"] == 5


@pytest.mark.asyncio
async def test_read_with_offset_and_limit(session):
    """Read a slice of a file with offset + limit."""
    result = await session.tool_read("a.txt", offset=2, limit=2)
    assert result["content"] == "beta\ngamma\n"
    assert result["total_lines"] == 5


@pytest.mark.asyncio
async def test_read_empty_file(session):
    """Read an empty file."""
    result = await session.tool_read("empty.txt")
    assert result["content"] == ""
    assert result["total_lines"] == 0


@pytest.mark.asyncio
async def test_read_binary_file_rejected(tmp_repo):
    """tool_read must reject binary files (return error dict)."""
    from cyber_audit.tools import ToolsSession

    bin_path = tmp_repo / "image.png"
    bin_path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 100)

    s = ToolsSession(str(tmp_repo))
    result = await s.tool_read("image.png")
    assert "error" in result
    assert "binary" in result["error"].lower()


@pytest.mark.asyncio
async def test_read_out_of_bounds_offset(session):
    """Offset beyond file length returns empty content."""
    result = await session.tool_read("a.txt", offset=100)
    assert result["content"] == ""
    assert result["total_lines"] == 5


@pytest.mark.asyncio
async def test_read_nonexistent_file(session):
    """Non-existent file should return an error."""
    result = await session.tool_read("nope.txt")
    assert "error" in result


@pytest.mark.asyncio
async def test_read_path_traversal_blocked(session):
    """Paths with .. must be rejected."""
    result = await session.tool_read("../etc/passwd")
    assert "error" in result


# ---------------------------------------------------------------------------
# tool_grep
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_grep_finds_matches(session):
    """Grep should find lines containing the pattern."""
    results = await session.tool_grep("ERROR", "sub/c.log")
    assert len(results) == 2
    assert results[0]["file"] == "sub/c.log"
    assert results[0]["line_content"] == "ERROR: something"
    assert results[1]["line_content"] == "ERROR: again"


@pytest.mark.asyncio
async def test_grep_no_matches(session):
    """No matches returns empty list."""
    results = await session.tool_grep("NOMATCH", "a.txt")
    assert results == []


@pytest.mark.asyncio
async def test_grep_with_glob(session):
    """Grep with a glob filter should only search matching files."""
    results = await session.tool_grep("ERROR", ".", glob="*.log")
    assert len(results) == 2
    assert all(r["file"].endswith(".log") for r in results)


@pytest.mark.asyncio
async def test_grep_path_traversal_blocked(session):
    """Paths with .. must be rejected."""
    result = await session.tool_grep("x", "../etc/passwd")
    assert "error" in result
    # It should return an error dict, not a list
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_grep_includes_line_numbers(session):
    """Each result must include file, line_num, line_content."""
    results = await session.tool_grep("hello", "sub/b.txt")
    assert len(results) == 1
    assert results[0]["file"] == "sub/b.txt"
    assert results[0]["line_num"] == 1
    assert results[0]["line_content"] == "hello world"


# ---------------------------------------------------------------------------
# tool_glob
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_glob_finds_files(session):
    """Glob should match files by pattern."""
    results = await session.tool_glob("*.txt", ".")
    # Should find a.txt, empty.txt, sub/b.txt (relative paths)
    assert len(results) >= 3
    assert "a.txt" in results
    assert "empty.txt" in results
    assert any("b.txt" in r for r in results)


@pytest.mark.asyncio
async def test_glob_in_subdirectory(session):
    """Glob within a subdirectory."""
    results = await session.tool_glob("*", "sub")
    assert len(results) >= 2
    assert any("b.txt" in r for r in results)
    assert any("c.log" in r for r in results)


@pytest.mark.asyncio
async def test_glob_no_matches(session):
    """No matches returns empty list."""
    results = await session.tool_glob("*.xyz", ".")
    assert results == []


@pytest.mark.asyncio
async def test_glob_path_traversal_blocked(session):
    """Paths with .. must be rejected."""
    result = await session.tool_glob("*", "../etc")
    assert "error" in result
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# tool_bash
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bash_runs_command(session):
    """Bash should run a simple command and return output + exit_code."""
    result = await session.tool_bash("echo hello")
    assert result["exit_code"] == 0
    assert "hello" in result["output"]


@pytest.mark.asyncio
async def test_bash_returns_exit_code(session):
    """Non-zero exit codes should be captured."""
    result = await session.tool_bash("exit 42")
    assert result["exit_code"] == 42


@pytest.mark.asyncio
async def test_bash_captures_stderr(session):
    """Stderr should be included in output."""
    result = await session.tool_bash("echo err >&2")
    assert "err" in result["output"]


@pytest.mark.asyncio
async def test_bash_blocks_rm_rf(session):
    """rm -rf must be blocked."""
    result = await session.tool_bash("rm -rf /")
    assert result["exit_code"] != 0
    assert "blocked" in result["output"].lower() or "error" in result["output"].lower()


@pytest.mark.asyncio
async def test_bash_blocks_sudo(session):
    """sudo must be blocked."""
    result = await session.tool_bash("sudo whoami")
    assert result["exit_code"] != 0
    assert "blocked" in result["output"].lower() or "error" in result["output"].lower()


@pytest.mark.asyncio
async def test_bash_blocks_chmod_777(session):
    """chmod 777 must be blocked."""
    result = await session.tool_bash("chmod 777 /tmp/x")
    assert result["exit_code"] != 0
    assert "blocked" in result["output"].lower() or "error" in result["output"].lower()


@pytest.mark.asyncio
async def test_bash_blocks_network_calls(session):
    """External network calls (curl, wget) must be blocked."""
    result = await session.tool_bash("curl http://evil.com")
    assert result["exit_code"] != 0
    assert "blocked" in result["output"].lower() or "error" in result["output"].lower()


@pytest.mark.asyncio
async def test_bash_workdir_respected(tmp_repo):
    """Bash should run in the specified workdir (relative to repo_path)."""
    from cyber_audit.tools import ToolsSession

    s = ToolsSession(str(tmp_repo))
    result = await s.tool_bash("pwd", workdir="sub")
    assert result["exit_code"] == 0
    # The output should contain the sub directory path
    assert "sub" in result["output"]


@pytest.mark.asyncio
async def test_bash_timeout(session):
    """Long-running commands should be killed by timeout."""
    result = await session.tool_bash("sleep 60", timeout=1)
    # Should be killed; exit_code will be non-zero (signal)
    assert result["exit_code"] != 0


# ---------------------------------------------------------------------------
# ToolsSession path enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_session_rejects_absolute_path_outside_repo(tmp_repo):
    """Absolute paths outside repo_path must be rejected."""
    from cyber_audit.tools import ToolsSession

    s = ToolsSession(str(tmp_repo))
    result = await s.tool_read("/etc/passwd")
    assert "error" in result


@pytest.mark.asyncio
async def test_session_allows_absolute_path_inside_repo(tmp_repo):
    """Absolute paths inside repo_path must be allowed."""
    from cyber_audit.tools import ToolsSession

    s = ToolsSession(str(tmp_repo))
    abs_path = str(tmp_repo / "a.txt")
    result = await s.tool_read(abs_path)
    assert "error" not in result
    assert result["total_lines"] == 5
