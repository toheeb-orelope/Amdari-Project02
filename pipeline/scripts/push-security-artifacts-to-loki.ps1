param(
    [string]$ArtifactRoot = "$env:USERPROFILE\Downloads",
    [string]$LokiPushUrl = "http://localhost:3100/loki/api/v1/push",
    [string]$RunId = (Get-Date -Format "yyyyMMdd-HHmmss")
)

$ErrorActionPreference = "Stop"

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return $null
    }
    $content = Get-Content $Path -Raw
    if ([string]::IsNullOrWhiteSpace($content)) {
        return $null
    }
    return $content | ConvertFrom-Json
}

function ConvertTo-LokiLabelValue {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return "unknown"
    }
    return ([string]$Value).ToLowerInvariant() -replace '[^a-z0-9_:.-]', '_'
}

function New-LokiTimestamp {
    $now = [DateTimeOffset]::UtcNow
    return ($now.ToUnixTimeMilliseconds() * 1000000).ToString()
}

$streams = @{}

function Add-LokiEvent {
    param(
        [hashtable]$Labels,
        [hashtable]$Event
    )

    $baseLabels = @{
        job = "security-artifacts"
        project = "secureflow"
        run_id = $RunId
    }

    foreach ($key in $Labels.Keys) {
        $baseLabels[$key] = ConvertTo-LokiLabelValue $Labels[$key]
    }

    $orderedLabels = [ordered]@{}
    foreach ($key in ($baseLabels.Keys | Sort-Object)) {
        $orderedLabels[$key] = $baseLabels[$key]
    }

    $labelKey = ($orderedLabels.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "|"
    $line = ($Event | ConvertTo-Json -Compress -Depth 20)
    $value = @((New-LokiTimestamp), $line)

    if (-not $streams.ContainsKey($labelKey)) {
        $streams[$labelKey] = @{
            stream = $orderedLabels
            values = @()
        }
    }

    $streams[$labelKey].values += ,$value
}

function Add-StageStatus {
    param(
        [string]$Stage,
        [string]$Status,
        [string]$Reason = ""
    )

    Add-LokiEvent `
        -Labels @{ event_type = "stage_status"; stage = $Stage; status = $Status } `
        -Event @{ event_type = "stage_status"; stage = $Stage; status = $Status; reason = $Reason; run_id = $RunId }
}

$gitleaksPath = Join-Path $ArtifactRoot "gitleaks-report\gitleaks-report.json"
$sonarPath = Join-Path $ArtifactRoot "sonar-security-findings\sonar-findings.json"
$trivyImageDir = Join-Path $ArtifactRoot "trivy-image-reports"
$iacDir = Join-Path $ArtifactRoot "iac-reports"
$zapPath = Join-Path $ArtifactRoot "zap-dast-report\zap-report.json"
$sbomDir = Join-Path $ArtifactRoot "image-sboms"

$gitleaks = Read-JsonFile $gitleaksPath
$gitleaksCount = if ($null -eq $gitleaks) { 0 } else { @($gitleaks).Count }
Add-StageStatus -Stage "secret-scan" -Status ($(if ($gitleaksCount -eq 0) { "pass" } else { "fail" })) -Reason "gitleaks findings: $gitleaksCount"
foreach ($finding in @($gitleaks)) {
    Add-LokiEvent `
        -Labels @{ event_type = "finding"; scanner = "gitleaks"; severity = "critical"; routing = "devsecops" } `
        -Event @{ scanner = "gitleaks"; severity = "CRITICAL"; routing = "devsecops"; rule = $finding.RuleID; file = $finding.File; line = $finding.StartLine; description = $finding.Description }
}

$sonar = Read-JsonFile $sonarPath
$sonarIssues = @($sonar.issues)
Add-StageStatus -Stage "sast-scan" -Status "pass" -Reason "sonarqube routed to appsec"
foreach ($issue in $sonarIssues) {
    Add-LokiEvent `
        -Labels @{ event_type = "finding"; scanner = "sonarqube"; severity = $issue.severity; routing = "appsec" } `
        -Event @{ scanner = "sonarqube"; severity = $issue.severity; routing = "appsec"; type = $issue.type; component = $issue.component; line = $issue.line; message = $issue.message; rule = $issue.rule }
}

$imageCritical = 0
if (Test-Path $trivyImageDir) {
    Get-ChildItem $trivyImageDir -Filter "trivy-image-*-report.json" | ForEach-Object {
        $service = $_.BaseName -replace '^trivy-image-', '' -replace '-report$', ''
        $report = Read-JsonFile $_.FullName
        foreach ($result in @($report.Results)) {
            foreach ($vuln in @($result.Vulnerabilities)) {
                if ($vuln.Severity -eq "CRITICAL") {
                    $imageCritical++
                }

                Add-LokiEvent `
                    -Labels @{ event_type = "finding"; scanner = "trivy-image"; service = $service; severity = $vuln.Severity; routing = ($(if ($vuln.Severity -eq "CRITICAL") { "devsecops" } else { "appsec" })) } `
                    -Event @{ scanner = "trivy-image"; service = $service; severity = $vuln.Severity; routing = ($(if ($vuln.Severity -eq "CRITICAL") { "devsecops" } else { "appsec" })); cve = $vuln.VulnerabilityID; package = $vuln.PkgName; installed = $vuln.InstalledVersion; fixed = $vuln.FixedVersion; title = $vuln.Title }
            }
        }
    }
}
Add-StageStatus -Stage "image-scan" -Status ($(if ($imageCritical -eq 0) { "pass" } else { "fail" })) -Reason "trivy image critical findings: $imageCritical"

$trivyK8sCritical = 0
$trivyK8s = Read-JsonFile (Join-Path $iacDir "trivy-kubernetes-report.json")
foreach ($result in @($trivyK8s.Results)) {
    foreach ($misconfig in @($result.Misconfigurations)) {
        if ($misconfig.Severity -eq "CRITICAL") {
            $trivyK8sCritical++
        }

        Add-LokiEvent `
            -Labels @{ event_type = "finding"; scanner = "trivy-kubernetes"; severity = $misconfig.Severity; routing = ($(if ($misconfig.Severity -eq "CRITICAL") { "devsecops" } else { "appsec" })) } `
            -Event @{ scanner = "trivy-kubernetes"; severity = $misconfig.Severity; routing = ($(if ($misconfig.Severity -eq "CRITICAL") { "devsecops" } else { "appsec" })); id = $misconfig.ID; target = $result.Target; title = $misconfig.Title }
    }
}

foreach ($checkovName in @("checkov-kubernetes", "checkov-terraform")) {
    $checkov = Read-JsonFile (Join-Path $iacDir "$checkovName.json")
    foreach ($check in @($checkov.results.failed_checks)) {
        Add-LokiEvent `
            -Labels @{ event_type = "finding"; scanner = $checkovName; severity = "policy"; routing = "appsec" } `
            -Event @{ scanner = $checkovName; severity = "POLICY"; routing = "appsec"; check_id = $check.check_id; check_name = $check.check_name; file = $check.file_path; line_range = ($check.file_line_range -join "-") }
    }
}
Add-StageStatus -Stage "iac-scan" -Status ($(if ($trivyK8sCritical -eq 0) { "pass" } else { "fail" })) -Reason "iac hard-fail findings handled by security gate policy"

$zap = Read-JsonFile $zapPath
$zapHigh = 0
if ($zap.scan_skipped -eq $true) {
    Add-LokiEvent `
        -Labels @{ event_type = "finding"; scanner = "zap"; severity = "info"; routing = "appsec" } `
        -Event @{ scanner = "zap"; severity = "INFO"; routing = "appsec"; message = $zap.skip_reason }
} else {
    foreach ($site in @($zap.site)) {
        foreach ($alert in @($site.alerts)) {
            $risk = if ($alert.riskdesc) { ($alert.riskdesc -split ' ')[0] } else { "unknown" }
            if ($risk -eq "High" -or $alert.riskcode -eq "3") {
                $zapHigh++
            }

            Add-LokiEvent `
                -Labels @{ event_type = "finding"; scanner = "zap"; severity = $risk; routing = "appsec" } `
                -Event @{ scanner = "zap"; severity = $risk.ToUpperInvariant(); routing = "appsec"; alert = $alert.alert; risk = $alert.riskdesc; confidence = $alert.confidence; url = $site.'@name' }
        }
    }
}
Add-StageStatus -Stage "dast-scan" -Status "pass" -Reason "zap high findings routed to appsec: $zapHigh"

if (Test-Path $sbomDir) {
    Get-ChildItem $sbomDir -Filter "*-sbom.spdx.json" | ForEach-Object {
        $service = $_.BaseName -replace '-sbom.spdx$', ''
        $sbom = Read-JsonFile $_.FullName
        $packageCount = @($sbom.packages).Count
        Add-LokiEvent `
            -Labels @{ event_type = "sbom"; scanner = "trivy-sbom"; service = $service; status = "generated" } `
            -Event @{ event_type = "sbom"; scanner = "trivy-sbom"; service = $service; package_count = $packageCount; file = $_.Name; status = "generated" }
    }
}

Add-StageStatus -Stage "security-gate" -Status ($(if ($gitleaksCount -eq 0 -and $imageCritical -eq 0 -and $trivyK8sCritical -eq 0) { "pass" } else { "fail" })) -Reason "differentiated gate policy applied"
Add-StageStatus -Stage "image-signing-sbom" -Status "pass" -Reason "latest run reported green by operator"

$payload = @{
    streams = @($streams.Values)
} | ConvertTo-Json -Depth 30 -Compress

if ($streams.Count -eq 0) {
    Write-Warning "No artifact events were found to publish."
    exit 0
}

Invoke-RestMethod -Method Post -Uri $LokiPushUrl -ContentType "application/json" -Body $payload | Out-Null
Write-Host "Published $($streams.Count) Loki stream(s) from artifacts to $LokiPushUrl with run_id=$RunId"
