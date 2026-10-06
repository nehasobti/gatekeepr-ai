"""Finding merging and deduplication logic."""

from __future__ import annotations

from gatekeeper.models import Finding


def merge_and_dedupe_findings(findings_lists: list[list[Finding]]) -> list[Finding]:
    """Combine multiple findings lists, deduplicating and merging overlapping findings."""
    all_findings: list[Finding] = [f for flist in findings_lists for f in flist]
    merged_map: dict[tuple[str, int, str], Finding] = {}

    for f in all_findings:
        # Key by file, start_line, category value
        key = (f.file, f.start_line, f.category.value)
        if key not in merged_map:
            merged_map[key] = f
        else:
            existing = merged_map[key]
            # Keep highest severity
            best_sev = existing.severity if existing.severity >= f.severity else f.severity
            # Keep highest confidence
            best_conf = existing.confidence if existing.confidence >= f.confidence else f.confidence
            # Merge sources uniquely
            merged_sources = sorted(set(existing.source + f.source))

            merged_map[key] = Finding(
                id=existing.id,
                file=existing.file,
                start_line=existing.start_line,
                end_line=max(existing.end_line, f.end_line),
                severity=best_sev,
                confidence=best_conf,
                category=existing.category,
                owasp=existing.owasp or f.owasp,
                cwe=existing.cwe or f.cwe,
                title=existing.title,
                explanation=existing.explanation,
                suggested_fix=existing.suggested_fix,
                source=merged_sources,
            )

    # Secondary deduplication by fingerprint ID if any remain
    by_id: dict[str, Finding] = {}
    for f in merged_map.values():
        if f.id not in by_id:
            by_id[f.id] = f
        else:
            cur = by_id[f.id]
            if f.severity > cur.severity:
                by_id[f.id] = f

    return list(by_id.values())
