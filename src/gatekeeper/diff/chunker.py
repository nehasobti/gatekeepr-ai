"""Chunking diffs into size-constrained batches for LLM review."""

from __future__ import annotations

from dataclasses import dataclass, field

from gatekeeper.diff.parser import FileDiff


@dataclass
class DiffChunk:
    chunk_id: int
    content: str
    files: list[str]
    estimated_tokens: int
    file_valid_lines: dict[str, set[int]] = field(default_factory=dict)


def format_hunk_with_line_numbers(hunk_text: str, target_start: int) -> str:
    """Format hunk lines showing line numbers for clear LLM reference."""
    lines = hunk_text.splitlines()
    formatted: list[str] = []
    curr_target = target_start

    for line in lines:
        if line.startswith("@@"):
            formatted.append(line)
        elif line.startswith("+"):
            formatted.append(f"{curr_target:5d} + {line[1:]}")
            curr_target += 1
        elif line.startswith("-"):
            formatted.append(f"      - {line[1:]}")
        else:
            # Context line
            prefix = line[1:] if line.startswith(" ") else line
            formatted.append(f"{curr_target:5d}   {prefix}")
            curr_target += 1

    return "\n".join(formatted)


def estimate_tokens(text: str) -> int:
    """Estimate token count based on standard ~4 characters per token."""
    return max(1, len(text) // 4)


def chunk_diff(
    diff_files: list[FileDiff],
    max_tokens_per_chunk: int = 12000,
) -> list[DiffChunk]:
    """Group file diffs or hunks into chunks under the per-request token limit."""
    chunks: list[DiffChunk] = []
    curr_files: list[str] = []
    curr_content_parts: list[str] = []
    curr_tokens = 0
    curr_valid_lines: dict[str, set[int]] = {}
    chunk_counter = 0

    def flush_chunk() -> None:
        nonlocal chunk_counter, curr_files, curr_content_parts, curr_tokens, curr_valid_lines
        if curr_content_parts:
            chunk_counter += 1
            chunks.append(
                DiffChunk(
                    chunk_id=chunk_counter,
                    content="\n\n".join(curr_content_parts),
                    files=list(curr_files),
                    estimated_tokens=curr_tokens,
                    file_valid_lines=dict(curr_valid_lines),
                )
            )
            curr_files = []
            curr_content_parts = []
            curr_tokens = 0
            curr_valid_lines = {}

    for file_diff in diff_files:
        formatted_hunks: list[str] = []
        for hunk in file_diff.raw_hunks:
            hunk_str = str(hunk)
            formatted = format_hunk_with_line_numbers(hunk_str, hunk.target_start)
            formatted_hunks.append(formatted)

        file_header = f"### File: {file_diff.path}"
        file_body = "\n".join(formatted_hunks)
        file_full_text = f"{file_header}\n{file_body}"
        file_tokens = estimate_tokens(file_full_text)

        # If file itself is larger than max_tokens_per_chunk, split by hunks
        if file_tokens > max_tokens_per_chunk and len(file_diff.raw_hunks) > 1:
            flush_chunk()
            for hunk_idx, hunk in enumerate(file_diff.raw_hunks):
                h_str = str(hunk)
                h_formatted = format_hunk_with_line_numbers(h_str, hunk.target_start)
                h_block = f"### File: {file_diff.path} (Hunk {hunk_idx + 1}/{len(file_diff.raw_hunks)})\n{h_formatted}"
                h_tokens = estimate_tokens(h_block)

                if curr_tokens + h_tokens > max_tokens_per_chunk and curr_content_parts:
                    flush_chunk()

                curr_files.append(file_diff.path)
                curr_content_parts.append(h_block)
                curr_tokens += h_tokens
                curr_valid_lines.setdefault(file_diff.path, set()).update(
                    file_diff.changed_line_numbers
                )
        else:
            if curr_tokens + file_tokens > max_tokens_per_chunk and curr_content_parts:
                flush_chunk()

            curr_files.append(file_diff.path)
            curr_content_parts.append(file_full_text)
            curr_tokens += file_tokens
            curr_valid_lines[file_diff.path] = file_diff.changed_line_numbers

    flush_chunk()
    return chunks
