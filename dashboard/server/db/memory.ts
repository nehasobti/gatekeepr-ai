// Memory store for dev / fallback when DATABASE_URL is not provided
export interface InMemoryRepo {
  id: string;
  name: string;
  platform: string;
  defaultBranch: string;
  createdAt: string;
}

export interface InMemoryFinding {
  id: string;
  runId: string;
  file: string;
  startLine: number;
  endLine: number;
  severity: string;
  confidence: string;
  category: string;
  title: string;
  explanation: string;
  suggestedFix?: string;
  source: string;
  cwe?: string;
  createdAt: string;
}

export interface InMemoryAuditRun {
  id: string;
  repoId: string;
  prId?: string;
  commitSha?: string;
  sourceBranch?: string;
  targetBranch?: string;
  verdict: 'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED';
  model?: string;
  durationSeconds?: number;
  inputTokens?: number;
  outputTokens?: number;
  cachedTokens?: number;
  estimatedCostUsd?: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  metadata?: Record<string, any>;
  createdAt: string;
  findings: InMemoryFinding[];
}

export const inMemoryDb: {
  repositories: InMemoryRepo[];
  auditRuns: InMemoryAuditRun[];
} = {
  repositories: [
    {
      id: 'org/payments-service',
      name: 'payments-service',
      platform: 'github',
      defaultBranch: 'main',
      createdAt: new Date(Date.now() - 86400000 * 7).toISOString(),
    },
    {
      id: 'org/auth-gateway',
      name: 'auth-gateway',
      platform: 'bitbucket',
      defaultBranch: 'master',
      createdAt: new Date(Date.now() - 86400000 * 6).toISOString(),
    },
  ],
  auditRuns: [
    {
      id: 'run-pay-101',
      repoId: 'org/payments-service',
      prId: '42',
      commitSha: '9b2f7a1c',
      sourceBranch: 'feature/stripe-v3-upgrade',
      targetBranch: 'main',
      verdict: 'FAIL',
      model: 'claude-3-5-sonnet-20241022',
      durationSeconds: 3.42,
      inputTokens: 3820,
      outputTokens: 540,
      cachedTokens: 1450,
      estimatedCostUsd: 0.0168,
      createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
      summary: {
        critical: 1,
        high: 1,
        medium: 0,
        low: 1,
        info: 0,
        total: 3,
      },
      metadata: {
        tool_version: '1.0.0',
        scanner_findings_count: 2,
        triaged_scanner_findings_count: 1,
      },
      findings: [
        {
          id: 'pay-find-1',
          runId: 'run-pay-101',
          file: 'services/stripe_client.py',
          startLine: 45,
          endLine: 48,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          category: 'SECRETS',
          title: 'Hardcoded Stripe Live Secret Key',
          explanation: 'Raw live API secret key sk_live_... embedded directly in client initialization. Anyone with repository access can extract billing credentials.',
          suggestedFix: 'stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")',
          source: 'gitleaks',
          cwe: 'CWE-798',
          createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
        },
        {
          id: 'pay-find-2',
          runId: 'run-pay-101',
          file: 'routes/webhooks.py',
          startLine: 112,
          endLine: 120,
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'AUTH',
          title: 'Missing Stripe Webhook Signature Verification',
          explanation: 'Webhook payload parsed before verifying signature header with stripe.Webhook.construct_event. Attackers can forge charge.succeeded events.',
          suggestedFix: 'event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)',
          source: 'claude',
          cwe: 'CWE-345',
          createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
        },
        {
          id: 'pay-find-3',
          runId: 'run-pay-101',
          file: 'models/transaction.py',
          startLine: 88,
          endLine: 90,
          severity: 'LOW',
          confidence: 'MEDIUM',
          category: 'CODE_SMELL',
          title: 'Float used for financial currency calculations',
          explanation: 'Using standard float for amount values leads to IEEE 754 precision inaccuracies. Use decimal.Decimal or integer cents.',
          suggestedFix: 'amount_cents: int = Field(ge=0)',
          source: 'claude',
          cwe: 'CWE-682',
          createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
        },
      ],
    },
    {
      id: 'run-pay-102',
      repoId: 'org/payments-service',
      prId: '43',
      commitSha: '4c8e11b0',
      sourceBranch: 'fix/refund-race-condition',
      targetBranch: 'main',
      verdict: 'PASS',
      model: 'claude-3-5-sonnet-20241022',
      durationSeconds: 2.15,
      inputTokens: 2150,
      outputTokens: 180,
      cachedTokens: 1200,
      estimatedCostUsd: 0.0075,
      createdAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0,
      },
      metadata: {
        tool_version: '1.0.0',
        scanner_findings_count: 0,
      },
      findings: [],
    },
    {
      id: 'run-auth-201',
      repoId: 'org/auth-gateway',
      prId: '89',
      commitSha: '61a38dc9',
      sourceBranch: 'feature/jwt-refresh-flow',
      targetBranch: 'master',
      verdict: 'FAIL',
      model: 'claude-3-5-sonnet-20241022',
      durationSeconds: 2.88,
      inputTokens: 3100,
      outputTokens: 410,
      cachedTokens: 1100,
      estimatedCostUsd: 0.0125,
      createdAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
      summary: {
        critical: 1,
        high: 0,
        medium: 1,
        low: 0,
        info: 0,
        total: 2,
      },
      metadata: {
        tool_version: '1.0.0',
        scanner_findings_count: 1,
      },
      findings: [
        {
          id: 'auth-find-1',
          runId: 'run-auth-201',
          file: 'src/tokens/jwt.ts',
          startLine: 34,
          endLine: 39,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          category: 'CRYPTO',
          title: 'JWT Algorithm none Permitted in Verification',
          explanation: 'jwt.verify called with algorithms: ["HS256", "none"] allowing tokens with forged unverified headers.',
          suggestedFix: 'jwt.verify(token, secret, { algorithms: ["HS256"] })',
          source: 'semgrep',
          cwe: 'CWE-327',
          createdAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
        },
        {
          id: 'auth-find-2',
          runId: 'run-auth-201',
          file: 'src/controllers/session.ts',
          startLine: 71,
          endLine: 75,
          severity: 'MEDIUM',
          confidence: 'HIGH',
          category: 'SESSION',
          title: 'Missing SameSite and Secure Flags on Refresh Cookie',
          explanation: 'Refresh cookie set without SameSite=Strict and Secure attribute, making it susceptible to cross-origin token harvesting.',
          suggestedFix: 'res.cookie("refreshToken", token, { httpOnly: true, secure: true, sameSite: "strict" })',
          source: 'claude',
          cwe: 'CWE-614',
          createdAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
        },
      ],
    },
    {
      id: 'run-auth-202',
      repoId: 'org/auth-gateway',
      prId: '90',
      commitSha: '8df91001',
      sourceBranch: 'patch/rotate-jwks-certs',
      targetBranch: 'master',
      verdict: 'PASS',
      model: 'claude-3-5-sonnet-20241022',
      durationSeconds: 1.84,
      inputTokens: 1980,
      outputTokens: 140,
      cachedTokens: 980,
      estimatedCostUsd: 0.0062,
      createdAt: new Date(Date.now() - 1000 * 60 * 360).toISOString(),
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0,
      },
      metadata: {
        tool_version: '1.0.0',
      },
      findings: [],
    },
  ],
};
