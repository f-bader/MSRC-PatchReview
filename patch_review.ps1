<#
.SYNOPSIS
    Analyze Microsoft Patch Tuesday vulnerability statistics.

.DESCRIPTION
    Retrieves a CVRF release document from the MSRC API and emits vulnerability
    statistics as a console report, JSON, PowerShell objects, or Markdown.

    Original Python version Copyright (C) 2021 Kevin Breen, Immersive Labs
    https://github.com/Immersive-Labs-Sec/msrc-api

    PowerShell port by Fabian Bader
#>

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingWriteHost',
    '',
    Justification = 'Write-Host is intentional for the colorized human-readable CLI renderer.')]
[CmdletBinding()]
param(
    [Alias('SecurityUpdate')]
    [Parameter(Position = 0, HelpMessage = 'Date string in YYYY-MMM or YYYY-MM format')]
    [string]$ReportDate,

    [ValidateSet('MSRC', 'CVE.org', 'None')]
    [string]$CVELink = 'MSRC',

    [ValidateRange(0, 10)]
    [double]$BaseScore = 8.0,

    [ValidateSet('human-readable', 'json', 'psobject', 'markdown')]
    [string]$Output = 'human-readable',

    [switch]$IncludeCriticality,

    [switch]$IncludeCustomerActionRequired
)

$ErrorActionPreference = 'Stop'

$BaseUrl = 'https://api.msrc.microsoft.com/cvrf/v2.0'
$Headers = @{ Accept = 'application/json' }
$CVELinkUris = @{
    'MSRC'    = 'https://msrc.microsoft.com/update-guide/vulnerability/'
    'CVE.org' = 'https://www.cve.org/CVERecord?id='
}
$VulnTypes = @(
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium'
)
$CriticalityValues = @('Critical', 'Important', 'Moderate', 'Low')

function ConvertTo-ReportDate {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value -match '^\d{4}-(?:0[1-9]|1[0-2])$') {
        $dateValue = "$Value-01"
        $format = 'yyyy-MM-dd'
    } elseif ($Value -match '^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$') {
        $dateValue = "$Value-01"
        $format = 'yyyy-MMM-dd'
    } else {
        throw "Invalid date format '$Value'. Use YYYY-MMM or YYYY-MM (for example, 2025-Oct or 2025-10)."
    }

    $parsedDate = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
            $dateValue,
            $format,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$parsedDate)) {
        throw "Invalid date format '$Value'. Use YYYY-MMM or YYYY-MM (for example, 2025-Oct or 2025-10)."
    }

    $parsedDate.ToString('yyyy-MMM', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-CvssScore {
    param([AllowNull()][Nullable[double]]$Score)

    if (-not $Score.HasValue) {
        return ' n/a'
    }

    return $Score.Value.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture).PadLeft(4)
}

function Get-SortedVulnerabilities {
    param([object[]]$Vulnerabilities)

    @($Vulnerabilities | Sort-Object @{ Expression = { if ($null -eq $_.SortScore) { [double]::NegativeInfinity } else { $_.SortScore } }; Descending = $true },
        @{ Expression = 'Title'; Descending = $false })
}

function Get-MarkdownTitle {
    param([Parameter(Mandatory)]$Vulnerability)

    $title = $Vulnerability.Title -replace '\|', '\|'
    if ([string]::IsNullOrEmpty($Vulnerability.URL)) {
        return $title
    }

    return "[$title]($($Vulnerability.URL))"
}

function Get-YesNoText {
    param([bool]$Value)

    if ($Value) { 'Yes' } else { 'No' }
}

function ConvertFrom-CvrfDocument {
    param(
        [Parameter(Mandatory)]$Document,
        [Parameter(Mandatory)][double]$ScoreThreshold,
        [Parameter(Mandatory)][bool]$UseCriticality,
        [AllowNull()][string]$LinkUri
    )

    $records = [System.Collections.Generic.List[object]]::new()
    $typeCounts = @{}
    foreach ($type in $VulnTypes) {
        $typeCounts[$type] = 0
    }

    foreach ($vulnerability in @($Document.Vulnerability)) {
        $title = $vulnerability.Title.Value
        if ([string]::IsNullOrWhiteSpace($title)) {
            continue
        }

        $foundTypes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $exploited = $false
        $exploitationLikely = $false
        $publiclyDisclosed = $false
        $criticality = 'N/A'

        foreach ($threat in @($vulnerability.Threats)) {
            $descriptions = foreach ($description in @($threat.Description)) {
                foreach ($part in @($description.Value -split ';')) {
                    $part.Trim()
                }
            }

            if ($threat.Type -eq 0) {
                if (@($threat.ProductID) -contains '11655') {
                    [void]$foundTypes.Add('Edge - Chromium')
                }
                foreach ($description in $descriptions) {
                    if ($VulnTypes -contains $description -and -not (@($threat.ProductID) -contains '11655')) {
                        [void]$foundTypes.Add($description)
                    }
                }
            }

            if ($threat.Type -eq 1) {
                if ($descriptions -contains 'Exploited:Yes') {
                    $exploited = $true
                }
                if ($descriptions -match 'Exploitation More Likely') {
                    $exploitationLikely = $true
                }
            }

            if ($descriptions -contains 'Publicly Disclosed:Yes') {
                $publiclyDisclosed = $true
            }

            if ($threat.Type -eq 3 -and $criticality -eq 'N/A') {
                $criticality = @($descriptions | Where-Object { $CriticalityValues -contains $_ } | Select-Object -First 1)[0]
                if ([string]::IsNullOrEmpty($criticality)) {
                    $criticality = 'N/A'
                }
            }
        }

        foreach ($type in $foundTypes) {
            $typeCounts[$type]++
        }

        $score = $null
        $rawScore = @($vulnerability.CVSSScoreSets | Select-Object -First 1 -ExpandProperty BaseScore)[0]
        if ($null -ne $rawScore -and "$rawScore" -ne '') {
            $score = [double]$rawScore
        }

        $customerActionRequired = @($vulnerability.Notes |
                Where-Object { $_.Title -eq 'Customer Action Required' } |
                ForEach-Object Value) -contains 'Yes'
        $isHighestRated = ($UseCriticality -and $criticality -eq 'Critical') -or
            ($null -ne $score -and $score -ge $ScoreThreshold)

        $records.Add([PSCustomObject]@{
                CVE                    = $vulnerability.CVE
                Title                  = $title
                CvssScore              = if ($null -eq $score) { 'n/a' } else { $score }
                SortScore              = $score
                Criticality            = $criticality
                Exploited              = $exploited
                ExploitationLikely     = $exploitationLikely
                CustomerActionRequired = $customerActionRequired
                HighestRated           = $isHighestRated
                PubliclyDisclosed      = $publiclyDisclosed
                URL                    = if ($LinkUri) { "$LinkUri$($vulnerability.CVE)" } else { $null }
            })
    }

    [PSCustomObject]@{
        Title      = if ($Document.DocumentTitle.Value) { $Document.DocumentTitle.Value } else { 'Release not found' }
        Records    = @($records)
        TypeCounts = $typeCounts
    }
}

function Write-HumanVulnerabilityRows {
    param(
        [object[]]$Vulnerabilities,
        [Parameter(Mandatory)][ConsoleColor]$Color,
        [int]$CveWidth,
        [switch]$ShowCriticality,
        [switch]$ShowCustomerActionRequired,
        [switch]$ShowLink
    )

    foreach ($vulnerability in $Vulnerabilities) {
        $criticalityText = if ($ShowCriticality) { " - $($vulnerability.Criticality.PadRight(9))" } else { '' }
        $linkText = if ($ShowLink -and $vulnerability.URL) { " - $($vulnerability.URL)" } else { '' }
        $fixedText = if ($ShowCustomerActionRequired -and -not $vulnerability.CustomerActionRequired) { ' [FIXED]' } else { '' }
        Write-Host "  [-] $($vulnerability.CVE.PadRight($CveWidth)) - $(Format-CvssScore $vulnerability.SortScore)$criticalityText - $($vulnerability.Title)$linkText$fixedText" -ForegroundColor $Color
    }
}

function Write-MarkdownTable {
    param([object[]]$Vulnerabilities)

    Write-Output '| CVE | CVSS Score | Criticality | Customer Action Required | Title |'
    Write-Output '|-----|------------|-------------|--------------------------|-------|'
    foreach ($vulnerability in $Vulnerabilities) {
        $formattedScore = (Format-CvssScore $vulnerability.SortScore).Trim()
        Write-Output "| $($vulnerability.CVE) | $formattedScore | $($vulnerability.Criticality) | $(Get-YesNoText $vulnerability.CustomerActionRequired) | $(Get-MarkdownTitle $vulnerability) |"
    }
}

function Write-HumanReport {
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)][double]$ScoreThreshold,
        [Parameter(Mandatory)][bool]$UseCriticality,
        [Parameter(Mandatory)][bool]$ShowCustomerActionRequired
    )

    $records = @($Report.Records)
    $cveWidth = [Math]::Max(3, @($records.CVE | ForEach-Object Length | Measure-Object -Maximum).Maximum)
    Write-Host '[+] Microsoft Patch Tuesday Stats' -ForegroundColor Green
    Write-Host '[+] https://github.com/f-bader/msrc-api-ps' -ForegroundColor Green
    Write-Host "[+] $($Report.Title)" -ForegroundColor Green
    Write-Host "[+] Found a total of $($records.Count) vulnerabilities" -ForegroundColor Green
    foreach ($type in $VulnTypes) {
        Write-Host "  [-] $($Report.TypeCounts[$type]) $type Vulnerabilities" -ForegroundColor Cyan
    }

    $exploited = Get-SortedVulnerabilities @($records | Where-Object Exploited)
    Write-Host "[+] Found $($exploited.Count) exploited in the wild" -ForegroundColor Green
    Write-HumanVulnerabilityRows $exploited Red $cveWidth -ShowCriticality:$UseCriticality -ShowCustomerActionRequired:$ShowCustomerActionRequired

    $disclosed = Get-SortedVulnerabilities @($records | Where-Object PubliclyDisclosed)
    Write-Host "[+] Found $($disclosed.Count) already publicly disclosed vulnerabilities" -ForegroundColor Green
    Write-HumanVulnerabilityRows $disclosed Red $cveWidth -ShowCriticality:$UseCriticality -ShowCustomerActionRequired:$ShowCustomerActionRequired

    $highestRated = Get-SortedVulnerabilities @($records | Where-Object HighestRated)
    $heading = if ($UseCriticality) { "[+] Highest Rated Vulnerabilities - CVE >= $ScoreThreshold or Critical" } else { "[+] Highest Rated Vulnerabilities - CVE >= $ScoreThreshold" }
    Write-Host $heading -ForegroundColor Green
    Write-HumanVulnerabilityRows $highestRated Yellow $cveWidth -ShowCriticality:$UseCriticality -ShowCustomerActionRequired:$ShowCustomerActionRequired

    $likely = Get-SortedVulnerabilities @($records | Where-Object ExploitationLikely)
    Write-Host "[+] Found $($likely.Count) vulnerabilities more likely to be exploited" -ForegroundColor Green
    Write-HumanVulnerabilityRows $likely Yellow $cveWidth -ShowCriticality:$UseCriticality -ShowCustomerActionRequired:$ShowCustomerActionRequired -ShowLink
}

function Write-MarkdownReport {
    param([Parameter(Mandatory)]$Report)

    $records = @($Report.Records)
    Write-Output "# $($Report.Title)"
    Write-Output ''
    Write-Output '## Vulnerabilities by category'
    Write-Output ''
    Write-Output "**Total Vulnerabilities:** $($records.Count)"
    foreach ($type in $VulnTypes) {
        Write-Output "- **$type Vulnerabilities:** $($Report.TypeCounts[$type])"
    }

    foreach ($section in @(
            @{ Name = 'Exploited Vulnerabilities'; Records = @(Get-SortedVulnerabilities @($records | Where-Object Exploited)) },
            @{ Name = 'Publicly Disclosed Vulnerabilities'; Records = @(Get-SortedVulnerabilities @($records | Where-Object PubliclyDisclosed)) },
            @{ Name = 'Highest Rated Vulnerabilities'; Records = @(Get-SortedVulnerabilities @($records | Where-Object HighestRated)) },
            @{ Name = 'Exploitation Likely Vulnerabilities'; Records = @(Get-SortedVulnerabilities @($records | Where-Object ExploitationLikely)) })) {
        Write-Output ''
        Write-Output "## $($section.Name)"
        Write-Output ''
        Write-MarkdownTable $section.Records
    }

    Write-Output ''
    Write-Output '## All Vulnerabilities'
    Write-Output ''
    Write-Output '| CVE | CVSS Score | Criticality | Exploited | Exploitation Likely | Customer Action Required | Publicly Disclosed | Title |'
    Write-Output '|-----|------------|-------------|-----------|---------------------|--------------------------|--------------------|-------|'
    foreach ($vulnerability in (Get-SortedVulnerabilities $records)) {
        Write-Output "| $($vulnerability.CVE) | $($vulnerability.CvssScore) | $($vulnerability.Criticality) | $(Get-YesNoText $vulnerability.Exploited) | $(Get-YesNoText $vulnerability.ExploitationLikely) | $(Get-YesNoText $vulnerability.CustomerActionRequired) | $(Get-YesNoText $vulnerability.PubliclyDisclosed) | $(Get-MarkdownTitle $vulnerability) |"
    }
}

function Invoke-PatchReview {
    param(
        [AllowNull()][string]$RequestedReportDate,
        [Parameter(Mandatory)][ValidateSet('MSRC', 'CVE.org', 'None')][string]$CveLink,
        [Parameter(Mandatory)][double]$ScoreThreshold,
        [Parameter(Mandatory)][ValidateSet('human-readable', 'json', 'psobject', 'markdown')][string]$OutputFormat,
        [Parameter(Mandatory)][bool]$UseCriticality,
        [Parameter(Mandatory)][bool]$ShowCustomerActionRequired
    )

    $releaseDate = if ([string]::IsNullOrWhiteSpace($RequestedReportDate)) {
        (Get-Date).ToString('yyyy-MMM', [System.Globalization.CultureInfo]::InvariantCulture)
    } else {
        ConvertTo-ReportDate $RequestedReportDate
    }
    Write-Verbose "Fetching data from MSRC API for $releaseDate"
    $document = Invoke-RestMethod -Uri "$BaseUrl/cvrf/$releaseDate" -Headers $Headers -Method Get -ErrorAction Stop
    if ($null -eq $document) {
        throw "No release notes found for $releaseDate."
    }

    $linkUri = if ($CveLink -eq 'None') { $null } else { $CVELinkUris[$CveLink] }
    $report = ConvertFrom-CvrfDocument $document $ScoreThreshold $UseCriticality $linkUri
    $outputData = $report.Records | Select-Object CVE, Title, CvssScore, Criticality, Exploited, ExploitationLikely, CustomerActionRequired, HighestRated, PubliclyDisclosed, URL

    switch ($OutputFormat) {
        'psobject' { $outputData }
        'json' { $outputData | ConvertTo-Json -Depth 3 }
        'markdown' { Write-MarkdownReport $report }
        'human-readable' { Write-HumanReport $report $ScoreThreshold $UseCriticality $ShowCustomerActionRequired }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-PatchReview $ReportDate $CVELink $BaseScore $Output ([bool]$IncludeCriticality) ([bool]$IncludeCustomerActionRequired)
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($statusCode) {
            Write-Host "[!] That's a $statusCode from MS - no release notes yet" -ForegroundColor Red
        } else {
            Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
        exit 1
    }
}
