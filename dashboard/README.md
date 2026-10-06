# Gatekeeper AI Web Dashboard

Real-time enterprise dashboard for **Gatekeeper AI** pull request audits, security gates, and LLM triage.

Built with **Nuxt 4 / Vue 3**, **Tailwind CSS**, **Drizzle ORM**, **Neon PostgreSQL**, and **Better Auth**.

---

## 🌟 Key Features

- **Executive Quality Metrics**: Gate pass rate percentage, total audits, count of issues blocked, total LLM spend, and token caching metrics.
- **Multi-Repository Aggregation**: Pass rate and cost tracking across all monitored services (e.g. `org/payments-service`, `org/auth-gateway`).
- **Security & Quality Categories**: Live breakdown of detected vulnerability classes (Secrets, Auth, Crypto, Injection, Code Smells).
- **Interactive PR Audit History**: Filter runs by repository or verdict (`PASS`, `FAIL`), view execution time, and click **Inspect** to open the drawer modal.
- **Finding Inspection Drawer**: Displays file coordinates, CWE tags, scanner source (Claude, Semgrep, Gitleaks, Bandit), clear explanations, and syntax-highlighted remediation recommendations.
- **Direct CLI Ingestion**: `gatekeeper audit --publish-url https://dashboard-domain/api/reports --publish-token <token>` posts audit payloads directly into the database.

---

## 🚀 Setup & Local Development

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```env
# Neon PostgreSQL connection string (or any Postgres instance)
DATABASE_URL=postgresql://user:password@ep-sample-pooler.region.neon.tech/neondb?sslmode=require

# Better Auth Secret key
BETTER_AUTH_SECRET=gatekeeper-super-secret-key-32chars-min
```
*(Note: If `DATABASE_URL` is omitted, the dashboard runs seamlessly with high-speed in-memory demo data.)*

### 3. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

### 4. Build for Production / Vercel
```bash
npm run build
```

---

## 📡 API Endpoints

- `GET /api/reports`: Lists audit runs with repository and findings details.
- `POST /api/reports`: Ingests `report.json` output from the Gatekeeper AI CLI engine.
- `GET /api/metrics`: Aggregates pass rates, top categories, and cost per repository.
