"""Audit pipeline orchestrator executing the 11-stage audit flow."""

from __future__ import annotations

import concurrent.futures
import logging
import os
import time
from pathlib import Path

import httpx

from gatekeeper import __version__
from gatekeeper.config import GatekeeperConfig
from gatekeeper.diff.chunker import DiffChunk, chunk_diff
from gatekeeper.diff.parser import DiffResult, parse_diff
from gatekeeper.engine.merge import merge_and_dedupe_findings
from gatekeeper.engine.rules import evaluate_gate
from gatekeeper.engine.suppressions import apply_suppressions
from gatekeeper.engine.triage import triage_scanner_findings
from gatekeeper.llm.cache import ChunkResultCache
from gatekeeper.llm.client import PROMPT_VERSION, LLMClient
from gatekeeper.llm.mock import MockLLMClient
from gatekeeper.models import (
    AuditMetadata,
    AuditResult,
    AuditSummary,
    Finding,
    Verdict,
)
from gatekeeper.notify import dispatch_notifications
from gatekeeper.platforms.base import Platform
from gatekeeper.report import print_console_report, write_all_reports
from gatekeeper.scanners import run_all_scanners
from gatekeeper.security.redactor import redact_text

logger = logging.getLogger("gatekeeper.engine.audit")


def run_audit(
    platform: Platform,
    config: GatekeeperConfig,
    base: str | None = None,
    head: str | None = None,
    dry_run: bool = False,
    mock: bool = False,
    repo_root: Path | None = None,
    enable_cache: bool = True,
    publish_url: str | None = None,
    publish_token: str | None = None,
) -> AuditResult:
    """Run full audit pipeline."""
    start_time_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    start_monotonic = time.monotonic()
    root = repo_root or Path.cwd()

    # Stage 1: Detect context
    context = platform.detect_context()
    target_branch = context.target_branch or base

    # Target branch filtering: if target_branch is defined and not in target_branches, skip
    if (
        target_branch
        and config.review.target_branches
        and target_branch not in config.review.target_branches
    ):
        duration = time.monotonic() - start_monotonic
        meta = AuditMetadata(
            tool_version=__version__,
            prompt_version=PROMPT_VERSION,
            model=config.model.name,
            config_hash=config.compute_hash(),
            pr_id=context.pr_id,
            commit_sha=context.commit_sha,
            target_branch=target_branch,
            source_branch=context.source_branch or head,
            start_time=start_time_iso,
            duration_seconds=round(duration, 3),
        )
        res = AuditResult(
            verdict=Verdict.SKIPPED,
            findings=[],
            summary=AuditSummary(),
            metadata=meta,
        )
        print_console_report(res)
        write_all_reports(res, config.outputs.output_dir, config.outputs.formats)
        platform.set_status(res)
        return res

    # Stage 2: Load diff
    try:
        raw_diff = platform.get_diff(base=base, head=head)
    except Exception as e:
        duration = time.monotonic() - start_monotonic
        meta = AuditMetadata(
            tool_version=__version__,
            start_time=start_time_iso,
            duration_seconds=round(duration, 3),
        )
        res = AuditResult(
            verdict=Verdict.ERROR,
            error_message=f"Failed to load diff: {e}",
            metadata=meta,
        )
        print_console_report(res)
        return res

    if not raw_diff.strip():
        # Clean diff / no changes
        duration = time.monotonic() - start_monotonic
        meta = AuditMetadata(
            tool_version=__version__,
            prompt_version=PROMPT_VERSION,
            model=config.model.name,
            config_hash=config.compute_hash(),
            pr_id=context.pr_id,
            commit_sha=context.commit_sha,
            target_branch=target_branch,
            source_branch=context.source_branch or head,
            start_time=start_time_iso,
            duration_seconds=round(duration, 3),
        )
        res = AuditResult(
            verdict=Verdict.PASS,
            findings=[],
            summary=AuditSummary(),
            metadata=meta,
        )
        print_console_report(res)
        write_all_reports(res, config.outputs.output_dir, config.outputs.formats)
        platform.post_summary(res)
        platform.set_status(res)
        return res

    # Stage 3: Filter diff
    diff_res: DiffResult = parse_diff(
        diff_text=raw_diff,
        include_patterns=config.review.include,
        exclude_patterns=config.review.exclude,
        max_files=config.review.max_files,
        max_diff_lines=config.review.max_diff_lines,
    )

    # Stage 4: Chunk diff
    chunks: list[DiffChunk] = chunk_diff(
        diff_files=diff_res.files,
        max_tokens_per_chunk=12000,
    )

    total_est_tokens = sum(c.estimated_tokens for c in chunks)

    # Handle dry run
    if dry_run:
        duration = time.monotonic() - start_monotonic
        meta = AuditMetadata(
            tool_version=__version__,
            prompt_version=PROMPT_VERSION,
            model=config.model.name,
            config_hash=config.compute_hash(),
            pr_id=context.pr_id,
            commit_sha=context.commit_sha,
            target_branch=target_branch,
            source_branch=context.source_branch or head,
            start_time=start_time_iso,
            duration_seconds=round(duration, 3),
            input_tokens=total_est_tokens,
            skipped_files=diff_res.skipped_files,
            extra={
                "dry_run": True,
                "chunk_count": len(chunks),
                "reviewed_files": [f.path for f in diff_res.files],
            },
        )
        res = AuditResult(
            verdict=Verdict.PASS,
            findings=[],
            summary=AuditSummary(),
            metadata=meta,
        )
        print_console_report(res)
        return res

    # Initialize LLM client
    llm: LLMClient | MockLLMClient
    if mock:
        llm = MockLLMClient(config=config)
    else:
        try:
            llm = LLMClient(config=config)
        except Exception as e:
            verdict = Verdict.PASS if not config.gate.fail_on_llm_error else Verdict.ERROR
            duration = time.monotonic() - start_monotonic
            meta = AuditMetadata(
                tool_version=__version__,
                prompt_version=PROMPT_VERSION,
                model=config.model.name,
                config_hash=config.compute_hash(),
                start_time=start_time_iso,
                duration_seconds=round(duration, 3),
            )
            res = AuditResult(
                verdict=verdict,
                error_message=f"LLM initialization failed: {e}",
                metadata=meta,
            )
            print_console_report(res)
            return res

    # Result Cache setup
    cache = ChunkResultCache(cache_dir=root / ".gatekeeper" / "cache")
    cached_hits_count = 0

    # Stage 5: Static scanners
    changed_file_paths = [f.path for f in diff_res.files]
    changed_lines_by_file = {f.path: f.changed_line_numbers for f in diff_res.files}
    scanner_findings: list[Finding] = []
    try:
        scanner_findings = run_all_scanners(
            config=config.scanners,
            changed_files=changed_file_paths,
            repo_root=root,
            changed_lines_by_file=changed_lines_by_file,
            pr_id=context.pr_id,
        )
    except Exception as e:
        logger.error(f"Scanner stage error: {e}")
        if config.gate.fail_on_scanner_error:
            duration = time.monotonic() - start_monotonic
            res = AuditResult(
                verdict=Verdict.ERROR,
                error_message=f"Scanner execution failed: {e}",
                metadata=AuditMetadata(
                    tool_version=__version__,
                    start_time=start_time_iso,
                    duration_seconds=round(duration, 3),
                ),
            )
            print_console_report(res)
            return res

    # Stage 6: Claude passes (security, quality) with Secret Redaction and Caching
    passes = config.review.passes or ["security", "quality"]
    raw_findings_by_pass: list[list[Finding]] = []

    def review_task(chunk: DiffChunk, p_name: str) -> tuple[list[Finding], bool]:
        safe_content = redact_text(chunk.content)

        if enable_cache:
            cached_findings = cache.get(
                chunk_content=safe_content,
                pass_name=p_name,
                prompt_version=PROMPT_VERSION,
                model_name=config.model.name,
                custom_rules=config.review.custom_rules,
            )
            if cached_findings is not None:
                return cached_findings, True

        fresh_findings = llm.review_chunk(
            chunk_content=safe_content,
            pass_name=p_name,
            valid_lines=chunk.file_valid_lines,
        )

        if enable_cache:
            cache.put(
                chunk_content=safe_content,
                pass_name=p_name,
                prompt_version=PROMPT_VERSION,
                model_name=config.model.name,
                findings=fresh_findings,
                custom_rules=config.review.custom_rules,
            )

        return fresh_findings, False

    tasks: list[tuple[DiffChunk, str]] = [(chunk, p_name) for p_name in passes for chunk in chunks]

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, max(1, len(tasks)))) as executor:
        future_to_task = {executor.submit(review_task, ch, p): (ch, p) for ch, p in tasks}
        for future in concurrent.futures.as_completed(future_to_task):
            try:
                pass_findings, was_cached = future.result()
                if was_cached:
                    cached_hits_count += 1
                raw_findings_by_pass.append(pass_findings)
            except Exception as e:
                if config.gate.fail_on_llm_error:
                    duration = time.monotonic() - start_monotonic
                    res = AuditResult(
                        verdict=Verdict.ERROR,
                        error_message=f"Review pass failed: {e}",
                        metadata=AuditMetadata(
                            tool_version=__version__,
                            start_time=start_time_iso,
                            duration_seconds=round(duration, 3),
                        ),
                    )
                    print_console_report(res)
                    return res

    # Stage 7: Triage scanner findings with LLM
    confirmed_scanner_findings: list[Finding] = scanner_findings
    if scanner_findings and config.scanners.triage_with_llm:
        confirmed_scanner_findings, _dismissed = triage_scanner_findings(
            findings=scanner_findings,
            repo_root=root,
            llm=llm,
        )

    # Stage 8: Merge and dedupe
    all_findings_lists = [*raw_findings_by_pass, confirmed_scanner_findings]
    merged_findings = merge_and_dedupe_findings(all_findings_lists)

    # Stage 9: Suppress
    active_findings, dropped_suppressed = apply_suppressions(
        findings=merged_findings,
        suppressions_config=config.suppressions,
        repo_root=root,
    )

    # Stage 10: Gate
    gate_verdict, violations = evaluate_gate(active_findings, config.gate)

    duration = time.monotonic() - start_monotonic
    tracker = llm.tracker
    meta = AuditMetadata(
        tool_version=__version__,
        prompt_version=PROMPT_VERSION,
        model=config.model.name,
        config_hash=config.compute_hash(),
        pr_id=context.pr_id,
        commit_sha=context.commit_sha,
        target_branch=target_branch,
        source_branch=context.source_branch or head,
        start_time=start_time_iso,
        duration_seconds=round(duration, 3),
        input_tokens=tracker.input_tokens,
        output_tokens=tracker.output_tokens,
        cached_tokens=tracker.total_cached,
        estimated_cost_usd=tracker.calculate_cost_usd(),
        skipped_files=diff_res.skipped_files,
        dropped_findings_count=len(dropped_suppressed),
        extra={
            "gate_violations": violations,
            "cached_chunk_hits": cached_hits_count,
            "scanner_findings_count": len(scanner_findings),
            "triaged_scanner_findings_count": len(confirmed_scanner_findings),
        },
    )

    result = AuditResult(
        verdict=gate_verdict,
        findings=active_findings,
        summary=AuditSummary.from_findings(active_findings),
        metadata=meta,
    )

    # Stage 11: Publish
    print_console_report(result)
    reports_written = write_all_reports(result, config.outputs.output_dir, config.outputs.formats)
    platform.post_summary(result)
    platform.post_inline_comments(result)
    platform.set_status(result)

    # HTTP POST publish to web dashboard if configured
    target_publish_url = publish_url or config.outputs.publish_url
    if target_publish_url:
        token = publish_token or os.environ.get(config.outputs.publish_token_env, "")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    target_publish_url,
                    json=result.model_dump(mode="json"),
                    headers=headers,
                )
                if resp.is_success:
                    logger.info(f"Audit report successfully published to {target_publish_url}")
                else:
                    logger.warning(
                        f"Failed to publish report to {target_publish_url}: status {resp.status_code}"
                    )
        except Exception as e:
            logger.warning(f"Error publishing report to {target_publish_url}: {e}")

    # Dispatch Notifications
    html_path = reports_written.get("html")
    dispatch_notifications(result, config.notify, html_report_path=html_path)

    return result
