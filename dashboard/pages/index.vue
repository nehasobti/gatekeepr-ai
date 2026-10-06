<template>
  <div class="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans">
    <!-- Top Navigation Bar -->
    <header class="border-b border-[#1F293D] bg-[#0E1420]/80 backdrop-blur-md sticky top-0 z-40">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div class="flex items-center space-x-3">
          <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-emerald-400 p-[1.5px] shadow-lg shadow-indigo-500/20">
            <div class="w-full h-full bg-[#0B0F17] rounded-[10px] flex items-center justify-center">
              <svg class="w-5 h-5 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
          </div>
          <div>
            <div class="flex items-center space-x-2">
              <span class="font-extrabold tracking-tight text-white text-lg">Gatekeeper<span class="text-indigo-400">AI</span></span>
              <span class="px-2 py-0.5 text-[10px] font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 rounded-full">v1.0.0</span>
            </div>
            <p class="text-[11px] text-slate-400 hidden sm:block">Automated AI Quality Gate & Audit Dashboard</p>
          </div>
        </div>

        <div class="flex items-center space-x-4">
          <div class="hidden md:flex items-center px-3 py-1.5 rounded-lg bg-[#161F30] border border-[#1F293D] text-xs space-x-2">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span class="text-slate-300">Engine Active</span>
            <span class="text-slate-500">|</span>
            <span class="text-slate-400 font-mono">Claude 3.5 Sonnet</span>
          </div>
          <button 
            @click="refreshData" 
            :disabled="loading"
            class="px-3.5 py-1.5 text-xs font-medium text-slate-200 bg-[#1A2333] hover:bg-[#222E42] border border-[#2A374F] rounded-lg transition-all flex items-center space-x-1.5 cursor-pointer disabled:opacity-50">
            <svg :class="{'animate-spin': loading}" class="w-3.5 h-3.5 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
            </svg>
            <span>Refresh</span>
          </button>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      <!-- Top Metrics Row -->
      <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Pass Rate Card -->
        <div class="bg-[#121926] border border-[#1F293D] rounded-2xl p-5 relative overflow-hidden glow-card">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Gate Pass Rate</span>
            <div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
          <div class="mt-4 flex items-baseline space-x-2">
            <span class="text-3xl font-extrabold text-white font-mono tracking-tight">{{ metrics?.passRate ?? 0 }}%</span>
            <span class="text-xs text-slate-400">({{ metrics?.passCount ?? 0 }} / {{ metrics?.totalAudits ?? 0 }} PRs)</span>
          </div>
          <div class="mt-3 w-full bg-[#1A2333] h-1.5 rounded-full overflow-hidden">
            <div class="bg-gradient-to-r from-emerald-500 to-teal-400 h-full rounded-full transition-all duration-500" :style="{ width: `${metrics?.passRate ?? 0}%` }"></div>
          </div>
        </div>

        <!-- Total Audits -->
        <div class="bg-[#121926] border border-[#1F293D] rounded-2xl p-5 relative overflow-hidden glow-card">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Audits</span>
            <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
              <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
          </div>
          <div class="mt-4 flex items-baseline space-x-2">
            <span class="text-3xl font-extrabold text-white font-mono tracking-tight">{{ metrics?.totalAudits ?? 0 }}</span>
            <span class="text-xs text-slate-400">Across {{ repositories.length }} repos</span>
          </div>
          <div class="mt-3 text-[11px] text-slate-400 flex items-center space-x-1">
            <span class="text-rose-400 font-semibold">{{ metrics?.failCount ?? 0 }} Blocked</span>
            <span>·</span>
            <span class="text-emerald-400 font-semibold">{{ metrics?.passCount ?? 0 }} Approved</span>
          </div>
        </div>

        <!-- Vulnerabilities Blocked -->
        <div class="bg-[#121926] border border-[#1F293D] rounded-2xl p-5 relative overflow-hidden glow-card">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Issues Blocked</span>
            <div class="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
              <svg class="w-4 h-4 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
          <div class="mt-4 flex items-baseline space-x-2">
            <span class="text-3xl font-extrabold text-rose-400 font-mono tracking-tight">{{ metrics?.totalIssuesBlocked ?? 0 }}</span>
            <span class="text-xs text-slate-400">Total findings</span>
          </div>
          <div class="mt-3 text-[11px] text-slate-400 flex items-center space-x-1.5">
            <span class="text-rose-400 font-medium">{{ severityMap?.CRITICAL ?? 0 }} Critical</span>
            <span>·</span>
            <span class="text-amber-400 font-medium">{{ severityMap?.HIGH ?? 0 }} High</span>
            <span>·</span>
            <span class="text-yellow-400 font-medium">{{ severityMap?.MEDIUM ?? 0 }} Med</span>
          </div>
        </div>

        <!-- Cost & Tokens -->
        <div class="bg-[#121926] border border-[#1F293D] rounded-2xl p-5 relative overflow-hidden glow-card">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total LLM Spend</span>
            <div class="w-8 h-8 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
              <svg class="w-4 h-4 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
          <div class="mt-4 flex items-baseline space-x-2">
            <span class="text-3xl font-extrabold text-white font-mono tracking-tight">${{ (metrics?.totalCostUsd ?? 0).toFixed(4) }}</span>
            <span class="text-xs text-slate-400">USD</span>
          </div>
          <div class="mt-3 text-[11px] text-slate-400 flex items-center space-x-1">
            <span class="text-indigo-300">{{ ((metrics?.totalTokens?.input ?? 0) / 1000).toFixed(1) }}k in</span>
            <span>·</span>
            <span class="text-indigo-300">{{ ((metrics?.totalTokens?.output ?? 0) / 1000).toFixed(1) }}k out</span>
            <span>·</span>
            <span class="text-emerald-400">{{ ((metrics?.totalTokens?.cached ?? 0) / 1000).toFixed(1) }}k cached</span>
          </div>
        </div>
      </section>

      <!-- Second Row: Repositories Breakdown & Top Categories -->
      <section class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Repositories Breakdown (2 cols) -->
        <div class="lg:col-span-2 bg-[#121926] border border-[#1F293D] rounded-2xl p-6">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-base font-bold text-white tracking-tight">Active Repositories</h2>
              <p class="text-xs text-slate-400">Quality stats and estimated spend per connected codebase</p>
            </div>
            <span class="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-2.5 py-1 rounded-md border border-indigo-500/20">
              {{ reposSummary.length }} Repos
            </span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-[#161F30] text-slate-400 border-b border-[#1F293D]">
                <tr>
                  <th scope="col" class="py-3 px-4 font-semibold">Repository</th>
                  <th scope="col" class="py-3 px-4 font-semibold text-center">Audits</th>
                  <th scope="col" class="py-3 px-4 font-semibold text-center">Pass Rate</th>
                  <th scope="col" class="py-3 px-4 font-semibold text-center">Issues</th>
                  <th scope="col" class="py-3 px-4 font-semibold text-right">Spend (USD)</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[#1F293D]/60">
                <tr v-for="repo in reposSummary" :key="repo.repoId" class="hover:bg-[#161F30]/40 transition-colors">
                  <td class="py-3.5 px-4 font-mono font-medium text-white flex items-center space-x-2">
                    <span class="w-2 h-2 rounded-full" :class="repo.passRate >= 70 ? 'bg-emerald-400' : 'bg-rose-400'"></span>
                    <span class="hover:text-indigo-400 cursor-pointer" @click="selectedRepo = selectedRepo === repo.repoId ? '' : repo.repoId">
                      {{ repo.repoId }}
                    </span>
                  </td>
                  <td class="py-3.5 px-4 text-center font-mono">{{ repo.totalAudits }}</td>
                  <td class="py-3.5 px-4 text-center">
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold"
                      :class="repo.passRate >= 70 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'">
                      {{ repo.passRate }}%
                    </span>
                  </td>
                  <td class="py-3.5 px-4 text-center font-mono text-slate-400">{{ repo.totalFindings }}</td>
                  <td class="py-3.5 px-4 text-right font-mono text-emerald-400">${{ repo.totalCostUsd }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Top Categories Breakdown (1 col) -->
        <div class="bg-[#121926] border border-[#1F293D] rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-4">
              <div>
                <h2 class="text-base font-bold text-white tracking-tight">Top Risk Categories</h2>
                <p class="text-xs text-slate-400">Frequency of security & quality violations</p>
              </div>
            </div>

            <div class="space-y-3.5 mt-2">
              <div v-for="item in topCategories.slice(0, 5)" :key="item.category" class="space-y-1">
                <div class="flex justify-between text-xs">
                  <span class="font-mono text-slate-300 font-semibold">{{ item.category }}</span>
                  <span class="text-slate-400 font-mono">{{ item.count }} issues</span>
                </div>
                <div class="w-full bg-[#1A2333] h-2 rounded-full overflow-hidden">
                  <div class="h-full rounded-full transition-all duration-500"
                    :class="getCategoryColorClass(item.category)"
                    :style="{ width: `${Math.min(100, (item.count / (metrics?.totalIssuesBlocked || 1)) * 100)}%` }">
                  </div>
                </div>
              </div>
              <div v-if="topCategories.length === 0" class="text-center py-8 text-xs text-slate-500">
                No violations detected yet.
              </div>
            </div>
          </div>

          <div class="mt-6 pt-4 border-t border-[#1F293D] flex items-center justify-between text-xs text-slate-400">
            <span>LLM Triage Mode</span>
            <span class="text-emerald-400 font-medium font-mono">Active (False Positives Filtered)</span>
          </div>
        </div>
      </section>

      <!-- Third Row: Audit Runs History & Findings Explorer -->
      <section class="bg-[#121926] border border-[#1F293D] rounded-2xl p-6">
        <!-- Section Header & Filters -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h2 class="text-base font-bold text-white tracking-tight">Pull Request Audit History</h2>
            <p class="text-xs text-slate-400">Detailed quality gate outcomes, tokens, and inspected diffs</p>
          </div>

          <div class="flex flex-wrap items-center gap-2.5">
            <!-- Filter by Repo -->
            <select v-model="selectedRepo" class="bg-[#161F30] border border-[#1F293D] text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500">
              <option value="">All Repositories</option>
              <option v-for="repo in repositories" :key="repo.id" :value="repo.id">{{ repo.id }}</option>
            </select>

            <!-- Filter by Status -->
            <select v-model="selectedVerdict" class="bg-[#161F30] border border-[#1F293D] text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500">
              <option value="">All Verdicts</option>
              <option value="PASS">PASS</option>
              <option value="FAIL">FAIL</option>
            </select>
          </div>
        </div>

        <!-- Audit Runs Table -->
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="text-xs uppercase bg-[#161F30] text-slate-400 border-b border-[#1F293D]">
              <tr>
                <th scope="col" class="py-3 px-4 font-semibold">Verdict</th>
                <th scope="col" class="py-3 px-4 font-semibold">Repository / PR</th>
                <th scope="col" class="py-3 px-4 font-semibold">Branch / Commit</th>
                <th scope="col" class="py-3 px-4 font-semibold text-center">Duration</th>
                <th scope="col" class="py-3 px-4 font-semibold text-center">Cost</th>
                <th scope="col" class="py-3 px-4 font-semibold text-center">Findings</th>
                <th scope="col" class="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-[#1F293D]/60 font-mono text-xs">
              <tr v-for="run in filteredRuns" :key="run.id" class="hover:bg-[#161F30]/40 transition-colors">
                <!-- Verdict -->
                <td class="py-3.5 px-4 font-sans">
                  <span class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-bold"
                    :class="run.verdict === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 glow-pass' : 'bg-rose-500/10 text-rose-400 border border-rose-500/30 glow-fail'">
                    <span class="w-1.5 h-1.5 rounded-full" :class="run.verdict === 'PASS' ? 'bg-emerald-400' : 'bg-rose-400'"></span>
                    <span>{{ run.verdict }}</span>
                  </span>
                </td>

                <!-- Repo & PR -->
                <td class="py-3.5 px-4 font-sans">
                  <div class="font-bold text-white text-sm">{{ run.repoId }}</div>
                  <div class="text-xs text-slate-400">PR #{{ run.prId || 'Local' }}</div>
                </td>

                <!-- Branch & Commit -->
                <td class="py-3.5 px-4">
                  <div class="text-indigo-300 font-medium truncate max-w-[160px]">{{ run.sourceBranch || 'head' }}</div>
                  <div class="text-slate-500 text-[11px]">{{ run.commitSha?.slice(0, 7) || 'latest' }}</div>
                </td>

                <!-- Duration -->
                <td class="py-3.5 px-4 text-center text-slate-300">
                  {{ run.durationSeconds ? `${run.durationSeconds}s` : '1.2s' }}
                </td>

                <!-- Cost -->
                <td class="py-3.5 px-4 text-center text-emerald-400">
                  ${{ (run.estimatedCostUsd || 0).toFixed(4) }}
                </td>

                <!-- Findings Summary -->
                <td class="py-3.5 px-4 text-center">
                  <div class="flex items-center justify-center space-x-1 font-sans">
                    <span v-if="run.summary?.critical > 0" class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {{ run.summary.critical }} C
                    </span>
                    <span v-if="run.summary?.high > 0" class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      {{ run.summary.high }} H
                    </span>
                    <span v-if="run.summary?.total === 0" class="text-slate-500 text-xs">Clean</span>
                  </div>
                </td>

                <!-- Action Button -->
                <td class="py-3.5 px-4 text-right font-sans">
                  <button 
                    @click="activeRunDrawer = run" 
                    class="px-3 py-1 bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded-lg text-xs font-semibold transition-colors cursor-pointer">
                    Inspect ({{ run.findings?.length || 0 }})
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>

    <!-- Findings Detail Modal / Drawer -->
    <div v-if="activeRunDrawer" class="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end transition-opacity">
      <div class="w-full max-w-2xl bg-[#0F1624] border-l border-[#1F293D] h-full flex flex-col shadow-2xl overflow-hidden">
        <!-- Drawer Header -->
        <div class="p-6 border-b border-[#1F293D] bg-[#141C2E] flex items-center justify-between">
          <div>
            <div class="flex items-center space-x-3">
              <span class="px-2.5 py-0.5 rounded-full text-xs font-bold"
                :class="activeRunDrawer.verdict === 'PASS' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'">
                {{ activeRunDrawer.verdict }}
              </span>
              <h3 class="text-base font-bold text-white">{{ activeRunDrawer.repoId }} — PR #{{ activeRunDrawer.prId }}</h3>
            </div>
            <p class="text-xs text-slate-400 mt-1 font-mono">
              Branch: {{ activeRunDrawer.sourceBranch }} → {{ activeRunDrawer.targetBranch }} ({{ activeRunDrawer.commitSha?.slice(0, 8) }})
            </p>
          </div>
          <button @click="activeRunDrawer = null" class="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-[#1F293D] transition-colors cursor-pointer">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- Drawer Content -->
        <div class="flex-1 overflow-y-auto p-6 space-y-4">
          <div v-if="!activeRunDrawer.findings || activeRunDrawer.findings.length === 0" class="text-center py-16">
            <div class="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto mb-3">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h4 class="text-sm font-bold text-white">Clean Quality Gate Run</h4>
            <p class="text-xs text-slate-400 mt-1">Zero high or critical findings reported. All checks passed!</p>
          </div>

          <div v-for="finding in activeRunDrawer.findings" :key="finding.id" class="bg-[#141C2E] border border-[#1F293D] rounded-xl p-5 space-y-3">
            <div class="flex items-start justify-between gap-3">
              <div class="flex items-center space-x-2">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase"
                  :class="getSeverityBadgeClass(finding.severity)">
                  {{ finding.severity }}
                </span>
                <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                  {{ finding.category }}
                </span>
                <span v-if="finding.cwe" class="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">
                  {{ finding.cwe }}
                </span>
              </div>
              <span class="text-[11px] font-mono text-slate-400">src: {{ finding.source }}</span>
            </div>

            <div>
              <h4 class="text-sm font-bold text-white">{{ finding.title }}</h4>
              <p class="text-xs font-mono text-indigo-400 mt-0.5">
                {{ finding.file }}:{{ finding.startLine }}-{{ finding.endLine }}
              </p>
            </div>

            <p class="text-xs text-slate-300 leading-relaxed bg-[#0B0F17]/50 p-3 rounded-lg border border-[#1F293D]/50">
              {{ finding.explanation }}
            </p>

            <div v-if="finding.suggestedFix" class="space-y-1">
              <span class="text-[11px] font-bold text-emerald-400 uppercase tracking-wide">Suggested Remediation:</span>
              <pre class="text-xs font-mono bg-[#090D14] p-3 rounded-lg border border-emerald-500/20 text-emerald-300 overflow-x-auto">{{ finding.suggestedFix }}</pre>
            </div>
          </div>
        </div>

        <!-- Drawer Footer -->
        <div class="p-4 border-t border-[#1F293D] bg-[#141C2E] flex justify-between items-center text-xs text-slate-400 font-mono">
          <span>Tokens: {{ activeRunDrawer.inputTokens }} in / {{ activeRunDrawer.outputTokens }} out</span>
          <span class="text-emerald-400">Run Spend: ${{ (activeRunDrawer.estimatedCostUsd || 0).toFixed(4) }}</span>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <footer class="border-t border-[#1F293D] bg-[#0E1420] py-4 text-center text-xs text-slate-500">
      <div class="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
        <p>Gatekeeper AI © 2026 — Advanced Automated PR Quality Gate</p>
        <p class="font-mono text-[11px] text-slate-400">Built with Nuxt 4, Vue 3, Drizzle ORM, Neon PostgreSQL & Claude</p>
      </div>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';

const loading = ref(false);
const runs = ref<any[]>([]);
const repositories = ref<any[]>([]);
const metrics = ref<any>(null);
const topCategories = ref<any[]>([]);
const severityMap = ref<any>({});
const reposSummary = ref<any[]>([]);

const selectedRepo = ref('');
const selectedVerdict = ref('');
const activeRunDrawer = ref<any>(null);

async function refreshData() {
  loading.value = true;
  try {
    const [reportsRes, metricsRes] = await Promise.all([
      $fetch('/api/reports'),
      $fetch('/api/metrics'),
    ]);
    runs.value = (reportsRes as any).runs || [];
    repositories.value = (reportsRes as any).repositories || [];
    metrics.value = (metricsRes as any).metrics || null;
    topCategories.value = (metricsRes as any).topCategories || [];
    severityMap.value = (metricsRes as any).severityBreakdown || {};
    reposSummary.value = (metricsRes as any).reposSummary || [];
  } catch (e) {
    console.error('Failed to load dashboard data:', e);
  } finally {
    loading.value = false;
  }
}

const filteredRuns = computed(() => {
  return runs.value.filter((r) => {
    if (selectedRepo.value && r.repoId !== selectedRepo.value) return false;
    if (selectedVerdict.value && r.verdict !== selectedVerdict.value) return false;
    return true;
  });
});

function getSeverityBadgeClass(sev: string) {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-rose-500/20 text-rose-300 border border-rose-500/40';
    case 'HIGH':
      return 'bg-amber-500/20 text-amber-300 border border-amber-500/40';
    case 'MEDIUM':
      return 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40';
    case 'LOW':
      return 'bg-blue-500/20 text-blue-300 border border-blue-500/40';
    default:
      return 'bg-slate-500/20 text-slate-300 border border-slate-500/40';
  }
}

function getCategoryColorClass(cat: string) {
  switch (cat?.toUpperCase()) {
    case 'SECRETS':
      return 'bg-rose-500';
    case 'AUTH':
    case 'CRYPTO':
      return 'bg-amber-500';
    case 'INJECTION':
      return 'bg-red-500';
    default:
      return 'bg-indigo-500';
  }
}

onMounted(() => {
  refreshData();
});
</script>
