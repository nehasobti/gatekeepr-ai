"""Diff parsing and filtering module using unidiff."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from unidiff.patch import Hunk, PatchedFile, PatchSet


@dataclass
class ChangedLine:
    line_number: int  # Target line number in new file
    content: str
    is_added: bool
    is_context: bool = False


@dataclass
class FileDiff:
    path: str
    is_binary: bool = False
    is_new: bool = False
    is_deleted: bool = False
    added_lines_count: int = 0
    removed_lines_count: int = 0
    changed_line_numbers: set[int] = field(default_factory=set)
    patch_text: str = ""
    raw_hunks: list[Hunk] = field(default_factory=list)


@dataclass
class DiffResult:
    files: list[FileDiff]
    skipped_files: list[str]
    total_added_lines: int
    total_removed_lines: int
    truncated: bool = False


def matches_glob_pattern(path_str: str, pattern: str) -> bool:
    """Match a POSIX relative path against a glob pattern supporting **."""
    posix_path = path_str.replace("\\", "/").lstrip("/")
    pat = pattern.replace("\\", "/")

    tokens: list[str] = []
    i = 0
    n = len(pat)
    while i < n:
        if pat[i : i + 3] == "**/":
            tokens.append("(?:.+/)?")
            i += 3
        elif pat[i : i + 2] == "**":
            tokens.append(".*")
            i += 2
        elif pat[i] == "*":
            tokens.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            tokens.append("[^/]")
            i += 1
        else:
            tokens.append(re.escape(pat[i]))
            i += 1

    regex = re.compile(f"^{''.join(tokens)}$", re.IGNORECASE)
    return bool(regex.match(posix_path))


def is_path_excluded(
    path_str: str, include_patterns: list[str], exclude_patterns: list[str]
) -> bool:
    """Check if a path is excluded based on include and exclude patterns."""
    posix_path = path_str.replace("\\", "/").lstrip("/")

    # If includes specified and path matches none, exclude it
    if include_patterns:
        included = any(matches_glob_pattern(posix_path, pat) for pat in include_patterns)
        if not included:
            return True

    # If matches any exclude pattern, exclude it
    return any(matches_glob_pattern(posix_path, pat) for pat in exclude_patterns)


def parse_diff(
    diff_text: str,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    max_files: int = 60,
    max_diff_lines: int = 3000,
) -> DiffResult:
    """Parse unified diff text, apply path exclusions, and enforce budget limits."""
    include = include_patterns or ["**/*"]
    exclude = exclude_patterns or []

    patch_set: list[PatchedFile] = list(PatchSet.from_string(diff_text))
    accepted_files: list[FileDiff] = []
    skipped_files: list[str] = []

    total_added = 0
    total_removed = 0
    accumulated_lines = 0
    truncated = False

    for patched_file in patch_set:
        file_path = patched_file.path or patched_file.target_file or patched_file.source_file
        # Normalize b/ or a/ prefixes if present
        if file_path.startswith("b/") or file_path.startswith("a/"):
            file_path = file_path[2:]

        # Skip deleted files
        if patched_file.is_removed_file:
            skipped_files.append(f"{file_path} (deleted)")
            continue

        # Skip binary files
        if patched_file.is_binary_file:
            skipped_files.append(f"{file_path} (binary)")
            continue

        # Check path exclusions
        if is_path_excluded(file_path, include, exclude):
            skipped_files.append(f"{file_path} (excluded by pattern)")
            continue

        # Check limits
        if len(accepted_files) >= max_files:
            skipped_files.append(f"{file_path} (exceeded max_files {max_files})")
            truncated = True
            continue

        file_diff_lines = patched_file.added + patched_file.removed
        if accumulated_lines + file_diff_lines > max_diff_lines and accepted_files:
            skipped_files.append(f"{file_path} (exceeded max_diff_lines {max_diff_lines})")
            truncated = True
            continue

        changed_lines: set[int] = set()
        for hunk in patched_file:
            target_line = hunk.target_start
            for line in hunk:
                if line.is_added:
                    changed_lines.add(target_line)
                    target_line += 1
                elif line.is_context:
                    target_line += 1
                # removed lines do not increment target line

        file_diff = FileDiff(
            path=file_path,
            is_binary=patched_file.is_binary_file,
            is_new=patched_file.is_added_file,
            is_deleted=patched_file.is_removed_file,
            added_lines_count=patched_file.added,
            removed_lines_count=patched_file.removed,
            changed_line_numbers=changed_lines,
            patch_text=str(patched_file),
            raw_hunks=list(patched_file),
        )

        accepted_files.append(file_diff)
        accumulated_lines += file_diff_lines
        total_added += patched_file.added
        total_removed += patched_file.removed

    return DiffResult(
        files=accepted_files,
        skipped_files=skipped_files,
        total_added_lines=total_added,
        total_removed_lines=total_removed,
        truncated=truncated,
    )
