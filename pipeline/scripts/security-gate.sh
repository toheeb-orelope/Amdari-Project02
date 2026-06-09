#!/usr/bin/env bash
set -euo pipefail

# Aggregates the security reports produced by this repository's GitHub Actions:
# Gitleaks, SonarQube, Trivy, and Checkov.

GATE_FAILED=0
COMMENT_REQUIRED=0
DEVSECOPS_FINDINGS=""
APPSEC_FINDINGS=""
APPSEC_INTAKE_URL="${APPSEC_INTAKE_URL:-}"

append_failure() {
    local message="$1"

    GATE_FAILED=1
    COMMENT_REQUIRED=1
    DEVSECOPS_FINDINGS="${DEVSECOPS_FINDINGS}
- ${message}"
}

append_appsec_finding() {
    local message="$1"

    COMMENT_REQUIRED=1
    APPSEC_FINDINGS="${APPSEC_FINDINGS}
- ${message}"
}

jq_count() {
    local file="$1"
    local query="$2"

    jq "$query" "$file" 2>/dev/null || echo "0"
}

# --- AGGREGATION PHASE ---

# 1. Gitleaks secrets scan
if [[ -f "gitleaks-report.json" ]]; then
    SECRET_COUNT=$(jq_count "gitleaks-report.json" 'length')

    if [[ "$SECRET_COUNT" -gt 0 ]]; then
        append_failure "**Gitleaks:** Found ${SECRET_COUNT} secret finding(s)."
    fi
fi

# 2. SonarQube SAST scan
if [[ -f "security-findings/sonar-findings.json" ]]; then
    SONAR_COUNT=$(jq_count "security-findings/sonar-findings.json" '[.issues[]? | select(.severity == "BLOCKER" or .severity == "CRITICAL")] | length')

    if [[ "$SONAR_COUNT" -gt 0 ]]; then
        append_failure "**SonarQube:** Found ${SONAR_COUNT} unresolved BLOCKER/CRITICAL issue(s)."
    fi
fi

# 3. Trivy image and Kubernetes scans
shopt -s nullglob
TRIVY_IMAGE_REPORTS=(trivy-image-*-report.json)
if [[ -f "trivy-image-report.json" ]]; then
    TRIVY_IMAGE_REPORTS+=("trivy-image-report.json")
fi

for TRIVY_IMAGE_REPORT in "${TRIVY_IMAGE_REPORTS[@]}"; do
    if [[ "$TRIVY_IMAGE_REPORT" == "trivy-image-report.json" ]]; then
        SERVICE_NAME="image"
    else
        SERVICE_NAME="${TRIVY_IMAGE_REPORT#trivy-image-}"
        SERVICE_NAME="${SERVICE_NAME%-report.json}"
    fi

    TRIVY_IMAGE_COUNT=$(jq_count "$TRIVY_IMAGE_REPORT" '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length')
    TRIVY_IMAGE_HIGH_COUNT=$(jq_count "$TRIVY_IMAGE_REPORT" '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length')

    if [[ "$TRIVY_IMAGE_COUNT" -gt 0 ]]; then
        append_failure "**Trivy Image (${SERVICE_NAME}):** Found ${TRIVY_IMAGE_COUNT} CRITICAL vulnerability finding(s)."
    fi

    if [[ "$TRIVY_IMAGE_HIGH_COUNT" -gt 0 ]]; then
        append_appsec_finding "**Trivy Image (${SERVICE_NAME}):** Found ${TRIVY_IMAGE_HIGH_COUNT} HIGH vulnerability finding(s)."
    fi
done
shopt -u nullglob

if [[ -f "trivy-kubernetes-report.json" ]]; then
    TRIVY_K8S_COUNT=$(jq_count "trivy-kubernetes-report.json" '[.Results[]?.Misconfigurations[]? | select(.Severity == "CRITICAL")] | length')
    TRIVY_K8S_HIGH_COUNT=$(jq_count "trivy-kubernetes-report.json" '[.Results[]?.Misconfigurations[]? | select(.Severity == "HIGH")] | length')

    if [[ "$TRIVY_K8S_COUNT" -gt 0 ]]; then
        append_failure "**Trivy Kubernetes:** Found ${TRIVY_K8S_COUNT} CRITICAL misconfiguration finding(s)."
    fi

    if [[ "$TRIVY_K8S_HIGH_COUNT" -gt 0 ]]; then
        append_appsec_finding "**Trivy Kubernetes:** Found ${TRIVY_K8S_HIGH_COUNT} HIGH misconfiguration finding(s)."
    fi
fi

# 4. Checkov IaC scans
if [[ -f "checkov-terraform.json" ]]; then
    TERRAFORM_CHECKOV_COUNT=$(jq_count "checkov-terraform.json" '
        [
            .results.failed_checks[]?
            | select(
                .check_id as $id
                | [
                    "CKV_AWS_17",
                    "CKV_AWS_38",
                    "CKV_AWS_39",
                    "CKV_AWS_260",
                    "CKV_AWS_277",
                    "CKV_AWS_382",
                    "CKV_AWS_16",
                    "CKV_AWS_37",
                    "CKV_AWS_58",
                    "CKV_AWS_129",
                    "CKV_AWS_62",
                    "CKV_AWS_63",
                    "CKV_AWS_274",
                    "CKV_AWS_286",
                    "CKV_AWS_287",
                    "CKV_AWS_288",
                    "CKV_AWS_289",
                    "CKV_AWS_290",
                    "CKV_AWS_355"
                ]
                | index($id)
            )
        ]
        | length
    ')

    if [[ "$TERRAFORM_CHECKOV_COUNT" -gt 0 ]]; then
        append_failure "**Checkov Terraform:** Found ${TERRAFORM_CHECKOV_COUNT} Stage 3/4 blocking finding(s)."
    fi
fi

if [[ -f "checkov-kubernetes.json" ]]; then
    KUBERNETES_CHECKOV_COUNT=$(jq_count "checkov-kubernetes.json" '
        [
            .results.failed_checks[]?
            | select(
                .check_id as $id
                | [
                    "CKV_K8S_16",
                    "CKV_K8S_20",
                    "CKV_K8S_22",
                    "CKV_K8S_23",
                    "CKV_K8S_30",
                    "CKV_K8S_31",
                    "CKV_K8S_37",
                    "CKV_K8S_40"
                ]
                | index($id)
            )
        ]
        | length
    ')

    if [[ "$KUBERNETES_CHECKOV_COUNT" -gt 0 ]]; then
        append_failure "**Checkov Kubernetes:** Found ${KUBERNETES_CHECKOV_COUNT} Stage 4 blocking finding(s)."
    fi
fi

# 5. OWASP ZAP DAST scan. ZAP is AppSec-owned and always soft-fail.
if [[ -f "zap-output/zap-report.json" ]]; then
    if jq -e '.scan_skipped == true' "zap-output/zap-report.json" >/dev/null 2>&1; then
        ZAP_SKIP_REASON=$(jq -r '.skip_reason // "ZAP baseline scan was skipped."' "zap-output/zap-report.json" 2>/dev/null || echo "ZAP baseline scan was skipped.")
        append_appsec_finding "**OWASP ZAP DAST:** ${ZAP_SKIP_REASON}"
    else
        ZAP_HIGH_COUNT=$(jq_count "zap-output/zap-report.json" '
            [
                .site[]?.alerts[]?
                | select((.riskcode // "0" | tonumber) == 3 or ((.riskdesc // "") | test("^High")))
            ]
            | length
        ')

        if [[ "$ZAP_HIGH_COUNT" -gt 0 ]]; then
            append_appsec_finding "**OWASP ZAP DAST:** Found ${ZAP_HIGH_COUNT} HIGH runtime finding(s) in staging. Routed to AppSec as soft-fail."
        fi
    fi
fi

# --- ENFORCEMENT & EVALUATION PHASE ---

if [[ -z "$DEVSECOPS_FINDINGS" ]]; then
    DEVSECOPS_FINDINGS="
- No blocking CRITICAL DevSecOps-owned findings detected."
fi

if [[ -z "$APPSEC_FINDINGS" ]]; then
    if [[ -n "$APPSEC_INTAKE_URL" ]]; then
        APPSEC_FINDINGS="
- No non-blocking AppSec-owned findings detected. For risk review or exceptions, use the [AppSec intake](${APPSEC_INTAKE_URL})."
    else
        APPSEC_FINDINGS="
- No non-blocking AppSec-owned findings detected. Configure APPSEC_INTAKE_URL to include the AppSec intake link."
    fi
elif [[ -n "$APPSEC_INTAKE_URL" ]]; then
    APPSEC_FINDINGS="${APPSEC_FINDINGS}
- Submit review or exception requests through the [AppSec intake](${APPSEC_INTAKE_URL})."
else
    APPSEC_FINDINGS="${APPSEC_FINDINGS}
- Configure APPSEC_INTAKE_URL to include the AppSec intake link."
fi

COMMENT_BODY="### Security Gate Evaluation

#### DevSecOps-owned findings
Blocking when CRITICAL.
${DEVSECOPS_FINDINGS}

#### AppSec-owned findings
Non-blocking. Use the intake link for review, exception requests, or ownership transfer.
${APPSEC_FINDINGS}
"

printf "%b\n" "$COMMENT_BODY" > pr_comment_payload.md

if [[ "$GATE_FAILED" -eq 1 ]]; then
    echo "Security Gate Evaluation: FAILED"
    FAIL_STATE=true
else
    echo "Security Gate Evaluation: PASSED"
    FAIL_STATE=false
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "FAIL_STATE=${FAIL_STATE}" >> "$GITHUB_ENV"
    if [[ "$COMMENT_REQUIRED" -eq 1 ]]; then
        echo "COMMENT_STATE=true" >> "$GITHUB_ENV"
    else
        echo "COMMENT_STATE=false" >> "$GITHUB_ENV"
    fi
fi
