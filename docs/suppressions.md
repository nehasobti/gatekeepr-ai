# Suppressions & Baselines

Gatekeeper AI provides two mechanisms to handle false positives, legacy debt, and accepted risks without modifying gate thresholds.

---

## 1. Inline Suppressions

You can suppress a finding directly on the affected code line by placing a comment containing `# gatekeeper-ignore: <reason>`. A reason is **mandatory**.

### Python Example
```python
# Intentionally using MD5 for non-cryptographic checksum
checksum = hashlib.md5(data).hexdigest()  # gatekeeper-ignore: Non-security checksum
```

### JavaScript / TypeScript Example
```typescript
// Legacy innerHTML injection safe due to trusted internal source
element.innerHTML = sanitizedHtml; // gatekeeper-ignore: Pre-sanitized by DOMPurify
```

### Rules for Inline Suppressions
- The suppression marker must specify a reason after the colon (`# gatekeeper-ignore: <reason>`).
- Comments lacking an explanation (e.g. `# gatekeeper-ignore` without text) are rejected and ignored.
- Suppressed findings are removed from the active gate count and recorded in audit metadata under `dropped_findings_count`.

---

## 2. Repository Baselines

When onboarding Gatekeeper AI onto an existing codebase with existing technical debt, you can capture current findings into a baseline file.

### Creating the Baseline
Run:

```bash
gatekeeper baseline create
```

This scans the entire repository once and writes fingerprints of all current findings to `.gatekeeper/baseline.json`.

### How Baselines Work
- Any finding whose fingerprint matches an entry in `.gatekeeper/baseline.json` is automatically suppressed.
- Only **new** vulnerabilities introduced in pull requests will trigger gate failures.
- As the team refactors legacy code, update the baseline by re-running `gatekeeper baseline create`.
