# Security Gate Pattern

>In the DevSecOps pipeline, a Security Gate is an automated or semi-automatic checkpoint that assesses code, infrastructure, or deployments in accordance with predetermined security standards. The gate prevents advancement (such as code commits, builds, or deployments) until problems are fixed if the requirements are not satisfied.

**Threshold strategy:**

- CRITICAL: Block deployment, page on-call
- HIGH: Block deployment, create urgent ticket
- MEDIUM: Allow deployment, fix in next sprint
- LOW: Allow deployment, add to backlog

>The principle is **risk-based prioritisation**. Not all findings are equal. A hardcoded test API key isn't as urgent as a SQL injection vulnerability.
>
>A sophisticated strategy for these checkpoints is a differentiated gate policy. Instead of using a single, general rule (such "block all builds with vulnerabilities"), it applies different rules according on the environment's sensitivity, risk level, or context.

1. How the Security-Gate Pattern Works

>The pattern functions as a fail-fast, automated system. Several security technologies (such as SAST for source code, SCA for open-source libraries, and Container Image scanning) are activated when a build passes through the pipeline.

- **The Checkpoint:** After these tools generate reports, a centralized "gate" script aggregates the findings.

- **The Decision:** The gate evaluates the findings against predefined thresholds. If the thresholds are exceeded, the deployment is blocked (failed).

2. The Concept of Differentiated Gate Policy

>A differentiated policy recognises that context is important, whereas traditional gates employ absolute metrics (such as "Any Critical vulnerability fails the build"). It modifies the security gate's strictness according to variables like:

- **Environment Sensitivity:** Staging or sandbox environments might allow a developer to bypass warnings for low-risk vulnerabilities to test new features. However, a production gate will instantly fail for the exact same vulnerabilities.

- **Component Criticality:** A public-facing web microservice might have a strict "no medium or critical" policy, whereas an internal administrative tool might only require checks for remote-code execution (RCE) flaws.

- **Vulnerability Source:** A differentiated policy can distinguish between vulnerabilities in code written by your in-house engineers versus third-party open-source libraries, applying different review workflows or exemptions for each.

3. Key Benefits

- **Reduced Alert Fatigue:** Developers aren't blocked by minor, theoretical vulnerabilities that don't apply to their specific use case.

- **Aligned Risk Management:** Ties security protocols directly to the business impact of the software being shipped.

- **Faster Time-to-Market:** Allows rapid delivery for low-risk, internal updates while maintaining rigorous defenses for critical, customer-facing applications.

## Week 1-2: Secret Scanning

### Implementation Roadmap

**Priority:** Highest (prevents credential leaks)

**Tasks:**

1. Install TruffleHog in CI/CD pipeline
2. Scan historical commits for exposed secrets
3. Rotate any exposed secrets immediately
4. Set up pre-commit hooks to prevent future leaks

**Success Metrics:**

- Zero secrets in new commits
- All historical secrets remediated

The principle here is **immediate ROI.** Secret scanning is the fastest win with the highest impact.

## Week 3-4: SAST Integration

**Priority:** High (catches bugs early)

**Tasks:**

1. Install Semgrep in pipeline
2. Start with default rules (--config=auto)
3. Review findings and fix critical issues
4. Customize rules for your specific tech stack

**Success Metrics:**

- <10 false positives per scan
- Critical issues block deployment

## Week 5-6: Container Scanning

**Priority:** High (protects infrastructure)

**Tasks:**

1. Integrate Trivy into Docker build process
2. Set severity threshold (CRITICAL blocks deployment)
3. Create base image update policy
4. Monitor vulnerability trends over time

**Success Metrics:**

- Zero critical vulnerabilities in production images
- 90% of vulnerabilities resolved within 7 days

## Week 7-8: DAST and Validation

**Priority:** Medium (validates runtime security)

**Tasks:**

1. Set up OWASP ZAP in staging environment
2. Configure authenticated scanning
3. Schedule weekly DAST scans
4. Create remediation workflow

**Success Metrics:**

- DAST scans complete in <30 minutes
- High findings resolved within 48 hours

**Implemented baseline:** The `security-gate-pipeline.yml` workflow runs an OWASP ZAP baseline scan against the repository variable `STAGING_URL`. ZAP findings are AppSec-owned and soft-fail: HIGH findings are added to the PR comment under AppSec-owned findings, but they do not set `FAIL_STATE=true` and do not block the merge.

## 1. Ownership Matrix: DevSecOps vs. AppSec Scanners

To avoid tool fatigue and friction, split ownership based on execution speed and risk context. DevSecOps owns embedded pipeline guardrails. AppSec owns deep compliance and risk visibility.


| Scanner Type | Primary Owner | Pipeline Stage | Enforcement Action | Goal / Focus |
| :--- | :--- | :--- | :--- | :--- |
| **SAST (Static Analysis)** | DevSecOps | Pull Request (PR) | Hard-Fail (High/Crit) | Catch code flaws before merge. |
| **SCA (Dependency/SBOM)** | DevSecOps | Pull Request (PR) | Hard-Fail (Blocklist) | Block known vulnerable packages. |
| **Secrets Detection** | DevSecOps | Pre-commit / PR | Hard-Fail (All) | Zero secrets in source control. |
| **Container Scanning** | DevSecOps | Build / Registry | Hard-Fail (OS Crit) | Base image and package hygiene. |
| **DAST (Dynamic Analysis)** | AppSec | QA / Staging | Soft-Fail / Alert | Find runtime/business logic flaws. |
| **Penetration Testing / ASOC** | AppSec | Production | None (Jira Ticket) | Compliance and deep asset risk. |

* **DevSecOps Role:** Configures the underlying infrastructure, optimizes scan speeds under 5 minutes, keeps definitions updated, and embeds tools directly into developers' local machines and CI/CD pipelines.
* **AppSec Role:** Tunes rulesets to eliminate false positives, conducts deep-dive triage, manages risk compliance metrics, and acts as the escalation point for complex vulnerabilities.

## 2. Guardrails: Hard-Fail vs. Soft-Fail Rules

Unpredictable pipeline failures alienate developers. Implement strict criteria for when a build completely blocks deployment versus when it issues a warning.

### Hard-Fail Rules (The Blockers)
* **Criteria:** Vulnerability has a known exploit available (EPSS score > 0.1), is rated Critical/High, and possesses a remediation path (fix available).
* **Secrets Policy:** 100% of verified active credentials (e.g., AWS keys, Slack tokens) hard-fail the build instantly.
* **Licence Policy:** Direct dependencies utilizing strictly prohibited licences (e.g., GPL-3.0 without legal sign-off) hard-fail the build.

### Soft-Fail Rules (The Warnings)
* **Criteria:** Medium or Low severity vulnerabilities, new or emerging zero-day flaws lacking a vendor patch, or findings with high false-positive rates.
* **Legacy Code Policy:** Vulnerabilities found in historical, untouched code paths are soft-failed and logged to the backlog to avoid halting active feature sprints.
* **DAST & Infrastructure:** All runtime or environment-level scans default to soft-fail, alerting the team via ticket rather than breaking code deployments.

## 3. Governance: Vulnerability Exception Process

When business requirements demand a deployment despite a hard-fail vulnerability, enforce a formal, time-bound risk acceptance workflow.

[Developer Requests Risk Acceptance]│▼[AppSec Triages & Validates Controls]│┌─────┴────────────────────────┐▼ (Approved)                   ▼ (Denied)[Issue Temporary Bypass Token] [Maintain Hard-Block / Fix Required]│▼[Auto-Expires & Re-Scans Build]

* **Submission:** The developer opens an exception request directly via Jira or a specialized portal, citing the business justification and compensating controls (e.g., "vulnerability is unreachable in runtime behind WAF").
* **Review Triage:** AppSec reviews the submission within a strict Service Level Objective (e.g., 4 hours for blockers).
* **Approval Triage:** If acceptable, AppSec issues a time-bound exception token or updates the scanner configuration policy with an explicit expiration date (typically 30 to 90 days).
* **Auto-Revocation:** Once the expiration date passes, the exception automatically deletes from the scanner platform, and the rule reverts to a hard-fail status on the next build.

### `/security-exception` PR Comment Trigger

Developers can start the exception workflow by commenting `/security-exception` on the pull request that is blocked by the security gate.

The trigger performs these actions:

* Adds the `security-exception-requested` label to the pull request.
* Posts the documented AppSec approval process back to the pull request.
* Includes the AppSec intake link when the repository variable `APPSEC_INTAKE_URL` is configured.
* Records the original request comment for audit context.

The trigger does **not** approve or bypass the security gate. A merge remains blocked until AppSec approves a time-bound exception and updates the relevant scanner policy, exception token, or allowlist.

Required exception request details:

* Finding ID or scanner reference.
* Affected service, image, dependency, or infrastructure component.
* Severity and current security gate impact.
* Business justification for shipping before remediation.
* Compensating controls or evidence that exploitability is reduced.
* Requested expiration date, normally 30 to 90 days.
* Named owner accountable for remediation before expiry.

Approval requirements:

* AppSec validates exploitability, compensating controls, and scope.
* AppSec records the decision in the intake system.
* Approved exceptions must be time-bound and tied to a specific finding or scanner rule.
* Denied exceptions keep the DevSecOps-owned CRITICAL finding blocked until fixed.
* Expired exceptions must be removed or allowed to auto-expire so the gate blocks again on the next scan.

## 4. Operations: Intake Template for AppSec Handoff

When a development team launches a new repository, major feature, or microservice, they must provide this checklist to AppSec to ensure appropriate security visibility.

```markdown
# AppSec Intake & Service Onboarding Request

## 1. Basic Metadata
* **Service / Project Name:** [e.g., Payment-Gateway-API]
* **Primary Slack Channel:** [#team-billing-dev]
* **Engineering Lead:** [Name / Email]
* **Product Owner:** [Name / Email]

## 2. Technical Profile
* **Repository URL(s):** [Link to GitHub/GitLab]
* **Primary Language & Runtime:** [e.g., Node.js v20, Go 1.22]
* **Deployment Target:** [e.g., AWS EKS, GCP Cloud Run, On-Prem]
* **Data Classification:** 
  - [ ] Public / Non-Sensitive
  - [ ] Internal Operational Data
  - [X] PII / Financial / PCI-DSS Regulated

## 3. Network & Architecture
* **Internet Exposed:** [Yes / No]
* **Authentication Method:** [e.g., Okta OIDC, mTLS, None]
* **Critical Dependencies:** [e.g., Connects to Production Database, Third-Party Stripe API]

## 4. Security Tooling Checklist (To be filled by DevSecOps/Dev)
* [X] Base image pulled from verified enterprise registry.
* [X] Pre-commit hooks for secrets scanning activated.
* [ ] SAST pipeline enabled (Currently failing / Currently passing).
* [ ] Open Source Licence compliance check run complete.
```
