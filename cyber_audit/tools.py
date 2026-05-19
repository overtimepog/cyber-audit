"""Cyber Audit tool functions — sandboxed file ops and bash execution.

Provides a ToolsSession class that enforces all paths stay within a
designated repo directory, plus four async tool functions.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Binary detection heuristic
# ---------------------------------------------------------------------------

_BINARY_SAMPLE_BYTES = 8192


def _is_binary(filepath: Path) -> bool:
    """Return True if *filepath* appears to be a binary (non-text) file.

    Heuristic: read the first 8 KiB and check for a null byte or >30 %
    non-printable characters (excluding common whitespace).
    """
    try:
        data = filepath.read_bytes()
    except (OSError, PermissionError):
        return False  # can't read → not our call to flag as binary

    if not data:
        return False

    sample = data[:_BINARY_SAMPLE_BYTES]
    if b"\x00" in sample:
        return True

    # Count non-printable, non-whitespace bytes
    text_chars = bytearray(
        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x7F))  # noqa: E222
    )
    non_text = bytes(b for b in sample if b not in text_chars)
    if len(non_text) / len(sample) > 0.30:
        return True

    return False


# ---------------------------------------------------------------------------
# Dangerous command patterns
# ---------------------------------------------------------------------------

_DANGEROUS_PATTERNS: List[re.Pattern] = [
    # rm -rf / rm --recursive --force
    re.compile(r"\brm\b.*(?:-r\b.*-f\b|-f\b.*-r\b|--recursive.*--force|--force.*--recursive)", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    # sudo
    re.compile(r"(?:^|\s)sudo\b", re.IGNORECASE),
    # chmod 777 / chmod 0777
    re.compile(r"\bchmod\b\s+.*\b777\b", re.IGNORECASE),
    # Network calls to external hosts
    re.compile(r"\bcurl\b", re.IGNORECASE),
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\bnc\b", re.IGNORECASE),
    re.compile(r"\bncat\b", re.IGNORECASE),
    re.compile(r"\btelnet\b", re.IGNORECASE),
    re.compile(r"\bssh\b", re.IGNORECASE),
    re.compile(r"\bscp\b", re.IGNORECASE),
    re.compile(r"\bsftp\b", re.IGNORECASE),
    re.compile(r"\bftp\b", re.IGNORECASE),
]


def _is_dangerous(command: str) -> Optional[str]:
    """Return a reason string if *command* is blocked, else None."""
    for pattern in _DANGEROUS_PATTERNS:
        if pattern.search(command):
            return f"blocked: dangerous command pattern detected ({pattern.pattern})"
    return None


# ---------------------------------------------------------------------------
# ToolsSession
# ---------------------------------------------------------------------------


class ToolsSession:
    """Sandboxed session bound to a repository directory.

    Every path passed to the tool functions is resolved relative to
    *repo_path* and rejected if it escapes (``..`` or absolute outside).
    """

    def __init__(self, repo_path: str) -> None:
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.is_dir():
            raise ValueError(f"repo_path is not a directory: {self.repo_path}")

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _resolve(self, rel: str) -> Path:
        """Resolve *rel* against repo_path and enforce containment.

        Returns the resolved ``Path``.

        Raises ``ValueError`` if the path escapes the repo.
        """
        # Reject explicit parent traversal in the string
        if ".." in Path(rel).parts:
            raise ValueError(f"path traversal blocked: {rel!r}")

        p = Path(rel)
        if p.is_absolute():
            resolved = p.resolve()
        else:
            resolved = (self.repo_path / p).resolve()

        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(
                f"path outside repo: {resolved!r} not under {self.repo_path!r}"
            ) from None

        return resolved

    # ------------------------------------------------------------------
    # tool_read
    # ------------------------------------------------------------------

    async def tool_read(
        self, path: str, offset: int = 1, limit: int = 500
    ) -> dict:
        """Read a text file inside the repo.

        Returns ``{"content": str, "total_lines": int}`` on success,
        or ``{"error": str}`` on failure (including binary files).
        """
        try:
            target = self._resolve(path)
        except (ValueError, OSError) as exc:
            return {"error": str(exc)}

        if not target.is_file():
            return {"error": f"not a file: {path}"}

        if _is_binary(target):
            return {"error": f"binary file rejected: {path}"}

        try:
            text = target.read_text()
        except UnicodeDecodeError:
            return {"error": f"binary file rejected: {path}"}
        except OSError as exc:
            return {"error": str(exc)}

        all_lines = text.splitlines(keepends=True)
        total = len(all_lines)

        start = max(0, offset - 1)
        end = start + limit
        selected = "".join(all_lines[start:end])

        return {"content": selected, "total_lines": total}

    # ------------------------------------------------------------------
    # tool_grep
    # ------------------------------------------------------------------

    async def tool_grep(
        self,
        pattern: str,
        path: str,
        glob: Optional[str] = None,
    ) -> list | dict:
        """Search for *pattern* in *path* (file or directory).

        Returns a list of ``{"file": str, "line_num": int, "line_content": str}``
        on success, or ``{"error": str}`` on failure.
        """
        try:
            target = self._resolve(path)
        except (ValueError, OSError) as exc:
            return {"error": str(exc)}

        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return {"error": f"invalid regex: {exc}"}

        results: list = []

        if target.is_dir():
            if glob is None:
                glob = "*"
            file_iter = target.rglob(glob)
        elif target.is_file():
            file_iter = [target]
        else:
            return {"error": f"path not found: {path}"}

        for fpath in sorted(file_iter):
            if not fpath.is_file():
                continue
            # Skip binary
            if _is_binary(fpath):
                continue
            try:
                lines = fpath.read_text().splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            for i, line in enumerate(lines, start=1):
                if regex.search(line):
                    rel = str(fpath.relative_to(self.repo_path))
                    results.append(
                        {"file": rel, "line_num": i, "line_content": line}
                    )

        return results

    # ------------------------------------------------------------------
    # tool_glob
    # ------------------------------------------------------------------

    async def tool_glob(self, pattern: str, path: str) -> list | dict:
        """Return relative file paths matching *pattern* inside *path*.

        Returns a list of ``str`` on success, or ``{"error": str}`` on failure.
        """
        try:
            target = self._resolve(path)
        except (ValueError, OSError) as exc:
            return {"error": str(exc)}

        if not target.is_dir():
            return {"error": f"not a directory: {path}"}

        matches = sorted(
            str(f.relative_to(self.repo_path))
            for f in target.rglob(pattern)
            if f.is_file()
        )
        return matches

    # ------------------------------------------------------------------
    # tool_bash
    # ------------------------------------------------------------------

    async def tool_bash(
        self,
        command: str,
        workdir: str = ".",
        timeout: int = 30,
    ) -> dict:
        """Execute a shell command inside the repo.

        Returns ``{"output": str, "exit_code": int}``.

        Dangeroud commands (rm -rf, sudo, chmod 777, network calls) are
        blocked before execution.
        """
        # Safety checks --------------------------------------------------
        danger = _is_dangerous(command)
        if danger:
            return {"output": danger, "exit_code": -1}

        # Resolve working directory --------------------------------------
        try:
            wd = self._resolve(workdir)
        except (ValueError, OSError) as exc:
            return {"output": str(exc), "exit_code": -1}

        if not wd.is_dir():
            return {"output": f"not a directory: {workdir}", "exit_code": -1}

        # Execute --------------------------------------------------------
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=str(wd),
                ),
                timeout=timeout,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            return {
                "output": f"command timed out after {timeout}s",
                "exit_code": -1,
            }

        output = stdout.decode("utf-8", errors="replace")
        return {"output": output, "exit_code": proc.returncode or 0}
