import { inMemoryDb } from '../db/memory';
import { getDb, schema } from '../db';
import { eq, desc } from 'drizzle-orm';

export default defineEventHandler(async (event) => {
  const method = getMethod(event);
  const db = getDb();

  if (method === 'POST') {
    // Ingest report.json payload sent from Gatekeeper CLI
    const body = await readBody(event);
    if (!body || !body.verdict) {
      throw createError({ statusCode: 400, statusMessage: 'Invalid audit report format' });
    }

    const meta = body.metadata || {};
    const repoSlug = meta.repo_id || meta.repo_slug || (meta.pr_id ? `repo-${meta.pr_id}` : 'default-repo');
    const runId = meta.run_id || `run-${Date.now()}`;
    const now = new Date().toISOString();

    const newRun = {
      id: runId,
      repoId: repoSlug,
      prId: meta.pr_id || null,
      commitSha: meta.commit_sha || null,
      sourceBranch: meta.source_branch || null,
      targetBranch: meta.target_branch || null,
      verdict: body.verdict,
      model: meta.model || null,
      durationSeconds: meta.duration_seconds || 0,
      inputTokens: meta.input_tokens || 0,
      outputTokens: meta.output_tokens || 0,
      cachedTokens: meta.cached_tokens || 0,
      estimatedCostUsd: meta.estimated_cost_usd || 0,
      summary: body.summary || {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: (body.findings || []).length,
      },
      metadata: meta,
      createdAt: now,
      findings: (body.findings || []).map((f: any, idx: number) => ({
        id: f.fingerprint || `${runId}-f-${idx}`,
        runId: runId,
        file: f.file || 'unknown',
        startLine: f.start_line || 1,
        endLine: f.end_line || 1,
        severity: f.severity || 'INFO',
        confidence: f.confidence || 'MEDIUM',
        category: f.category || 'GENERAL',
        title: f.title || 'Untitled finding',
        explanation: f.explanation || '',
        suggestedFix: f.suggested_fix || null,
        source: f.source || 'claude',
        cwe: f.cwe || null,
        createdAt: now,
      })),
    };

    if (db) {
      try {
        // Upsert repository
        await db.insert(schema.repositories).values({
          id: repoSlug,
          name: repoSlug.split('/').pop() || repoSlug,
          platform: 'github',
          defaultBranch: 'main',
        }).onConflictDoNothing();

        // Insert audit run
        await db.insert(schema.auditRuns).values({
          id: newRun.id,
          repoId: newRun.repoId,
          prId: newRun.prId,
          commitSha: newRun.commitSha,
          sourceBranch: newRun.sourceBranch,
          targetBranch: newRun.targetBranch,
          verdict: newRun.verdict,
          model: newRun.model,
          durationSeconds: String(newRun.durationSeconds),
          inputTokens: newRun.inputTokens,
          outputTokens: newRun.outputTokens,
          cachedTokens: newRun.cachedTokens,
          estimatedCostUsd: String(newRun.estimatedCostUsd),
          summary: newRun.summary,
          metadata: newRun.metadata,
        });

        // Insert findings
        for (const f of newRun.findings) {
          await db.insert(schema.findings).values({
            id: f.id,
            runId: f.runId,
            file: f.file,
            startLine: f.startLine,
            endLine: f.endLine,
            severity: f.severity,
            confidence: f.confidence,
            category: f.category,
            title: f.title,
            explanation: f.explanation,
            suggestedFix: f.suggestedFix,
            source: f.source,
            cwe: f.cwe,
          });
        }
      } catch (err) {
        console.warn('Failed to insert into postgres, falling back to memory store:', err);
      }
    }

    // Always maintain in-memory representation for instant responsiveness
    if (!inMemoryDb.repositories.some((r) => r.id === repoSlug)) {
      inMemoryDb.repositories.push({
        id: repoSlug,
        name: repoSlug.split('/').pop() || repoSlug,
        platform: 'github',
        defaultBranch: 'main',
        createdAt: now,
      });
    }
    inMemoryDb.auditRuns.unshift(newRun);

    return { success: true, runId: newRun.id, verdict: newRun.verdict };
  }

  // GET /api/reports
  const query = getQuery(event);
  const repoFilter = query.repo as string | undefined;
  const verdictFilter = query.verdict as string | undefined;

  let runs = [...inMemoryDb.auditRuns];

  if (db) {
    try {
      const dbRuns = await db.select().from(schema.auditRuns).orderBy(desc(schema.auditRuns.createdAt)).limit(50);
      if (dbRuns && dbRuns.length > 0) {
        // Map db runs
        const allFindings = await db.select().from(schema.findings);
        runs = dbRuns.map((r) => ({
          id: r.id,
          repoId: r.repoId,
          prId: r.prId || undefined,
          commitSha: r.commitSha || undefined,
          sourceBranch: r.sourceBranch || undefined,
          targetBranch: r.targetBranch || undefined,
          verdict: r.verdict as any,
          model: r.model || undefined,
          durationSeconds: r.durationSeconds ? Number(r.durationSeconds) : undefined,
          inputTokens: r.inputTokens || 0,
          outputTokens: r.outputTokens || 0,
          cachedTokens: r.cachedTokens || 0,
          estimatedCostUsd: r.estimatedCostUsd ? Number(r.estimatedCostUsd) : 0,
          summary: (r.summary as any) || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
          metadata: (r.metadata as any) || {},
          createdAt: r.createdAt.toISOString(),
          findings: allFindings.filter((f) => f.runId === r.id).map((f) => ({
            id: f.id,
            runId: f.runId,
            file: f.file,
            startLine: f.startLine,
            endLine: f.endLine,
            severity: f.severity,
            confidence: f.confidence,
            category: f.category,
            title: f.title,
            explanation: f.explanation,
            suggestedFix: f.suggestedFix || undefined,
            source: f.source || 'claude',
            cwe: f.cwe || undefined,
            createdAt: f.createdAt.toISOString(),
          })),
        }));
      }
    } catch (e) {
      console.warn('DB select failed, reading from memory store');
    }
  }

  if (repoFilter) {
    runs = runs.filter((r) => r.repoId === repoFilter);
  }
  if (verdictFilter) {
    runs = runs.filter((r) => r.verdict === verdictFilter.toUpperCase());
  }

  return {
    runs,
    repositories: inMemoryDb.repositories,
  };
});
