import { inMemoryDb } from '../db/memory';

export default defineEventHandler(async () => {
  const runs = inMemoryDb.auditRuns;
  const repos = inMemoryDb.repositories;

  const totalAudits = runs.length;
  const passCount = runs.filter((r) => r.verdict === 'PASS').length;
  const failCount = runs.filter((r) => r.verdict === 'FAIL').length;
  const passRate = totalAudits > 0 ? Math.round((passCount / totalAudits) * 100) : 100;

  let totalCostUsd = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalCachedTokens = 0;
  let totalIssuesBlocked = 0;

  const categoryMap: Record<string, number> = {};
  const severityMap: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  const repoStats: Record<
    string,
    {
      repoId: string;
      name: string;
      totalAudits: number;
      passedAudits: number;
      totalCostUsd: number;
      totalFindings: number;
    }
  > = {};

  for (const repo of repos) {
    repoStats[repo.id] = {
      repoId: repo.id,
      name: repo.name,
      totalAudits: 0,
      passedAudits: 0,
      totalCostUsd: 0,
      totalFindings: 0,
    };
  }

  for (const run of runs) {
    totalCostUsd += run.estimatedCostUsd || 0;
    totalInputTokens += run.inputTokens || 0;
    totalOutputTokens += run.outputTokens || 0;
    totalCachedTokens += run.cachedTokens || 0;

    if (repoStats[run.repoId]) {
      repoStats[run.repoId].totalAudits += 1;
      if (run.verdict === 'PASS') {
        repoStats[run.repoId].passedAudits += 1;
      }
      repoStats[run.repoId].totalCostUsd += run.estimatedCostUsd || 0;
    }

    for (const f of run.findings) {
      totalIssuesBlocked += 1;
      const cat = f.category.toUpperCase();
      categoryMap[cat] = (categoryMap[cat] || 0) + 1;

      const sev = f.severity.toUpperCase();
      if (severityMap[sev] !== undefined) {
        severityMap[sev] += 1;
      }

      if (repoStats[run.repoId]) {
        repoStats[run.repoId].totalFindings += 1;
      }
    }
  }

  const topCategories = Object.entries(categoryMap)
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  const reposSummary = Object.values(repoStats).map((r) => ({
    ...r,
    passRate: r.totalAudits > 0 ? Math.round((r.passedAudits / r.totalAudits) * 100) : 100,
    totalCostUsd: Number(r.totalCostUsd.toFixed(4)),
  }));

  return {
    metrics: {
      totalAudits,
      passCount,
      failCount,
      passRate,
      totalIssuesBlocked,
      totalCostUsd: Number(totalCostUsd.toFixed(4)),
      totalTokens: {
        input: totalInputTokens,
        output: totalOutputTokens,
        cached: totalCachedTokens,
      },
    },
    topCategories,
    severityBreakdown: severityMap,
    reposSummary,
  };
});
