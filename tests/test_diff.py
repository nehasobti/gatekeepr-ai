"""Unit tests for diff parsing, pattern filtering, and chunking."""

from gatekeeper.diff.chunker import chunk_diff, format_hunk_with_line_numbers
from gatekeeper.diff.parser import FileDiff, is_path_excluded, matches_glob_pattern, parse_diff

SAMPLE_DIFF = """diff --git a/src/app.py b/src/app.py
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/src/app.py
@@ -0,0 +1,5 @@
+import os
+def run():
+    password = "secret"
+    return password
+
diff --git a/poetry.lock b/poetry.lock
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/poetry.lock
@@ -0,0 +1,1 @@
+[[package]]
diff --git a/deleted.txt b/deleted.txt
deleted file mode 100644
--- a/deleted.txt
+++ /dev/null
@@ -1,1 +0,0 @@
-goodbye
Binary files a/image.png and b/image.png differ
"""


def test_glob_pattern_matching() -> None:
    assert matches_glob_pattern("poetry.lock", "**/*.lock")
    assert matches_glob_pattern("package-lock.json", "**/*lock*")
    assert matches_glob_pattern("subdir/dist/bundle.js", "**/dist/**")
    assert matches_glob_pattern("src/main.min.js", "**/*.min.js")
    assert not matches_glob_pattern("src/app.py", "**/*.lock")


def test_is_path_excluded() -> None:
    excludes = ["**/*.lock", "**/dist/**"]
    includes = ["**/*"]
    assert is_path_excluded("poetry.lock", includes, excludes)
    assert not is_path_excluded("src/app.py", includes, excludes)


def test_parse_diff_with_exclusions() -> None:
    res = parse_diff(
        SAMPLE_DIFF,
        include_patterns=["**/*"],
        exclude_patterns=["**/*.lock"],
        max_files=10,
        max_diff_lines=1000,
    )
    assert len(res.files) == 1
    assert res.files[0].path == "src/app.py"
    # Ensure deleted and binary files are skipped
    skipped_str = " ".join(res.skipped_files)
    assert "deleted.txt" in skipped_str
    assert "image.png" in skipped_str


def test_format_hunk_with_line_numbers() -> None:
    hunk_text = """@@ -0,0 +1,3 @@
+line1
 context
+line3"""
    formatted = format_hunk_with_line_numbers(hunk_text, 1)
    assert "    1 + line1" in formatted
    assert "    2   context" in formatted
    assert "    3 + line3" in formatted


def test_chunking() -> None:
    res = parse_diff(SAMPLE_DIFF, exclude_patterns=["**/*.lock"])
    chunks = chunk_diff(res.files, max_tokens_per_chunk=1000)
    assert len(chunks) == 1
    assert "src/app.py" in chunks[0].files
    assert chunks[0].estimated_tokens > 0
    assert 3 in chunks[0].file_valid_lines["src/app.py"]


def test_chunking_large_file_splits_by_hunk() -> None:
    parsed = parse_diff(SAMPLE_DIFF)
    file_diff = parsed.files[0]
    # Create multiple simulated hunks
    hunk1 = file_diff.raw_hunks[0]
    big_file = FileDiff(
        path="src/large.py",
        is_binary=False,
        is_new=True,
        is_deleted=False,
        added_lines_count=200,
        removed_lines_count=0,
        changed_line_numbers=set(range(1, 201)),
        raw_hunks=[hunk1, hunk1, hunk1],
    )
    # Force small max_tokens_per_chunk to trigger hunk splitting
    chunks = chunk_diff([big_file], max_tokens_per_chunk=10)
    assert len(chunks) >= 2
