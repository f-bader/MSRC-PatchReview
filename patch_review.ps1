<#
.SYNOPSIS
    PatchReview - Analyze Microsoft Patch Tuesday vulnerability statistics

.DESCRIPTION
    This script retrieves and analyzes vulnerability data from the Microsoft Security Response Center (MSRC) API
    for a given Patch Tuesday release. It provides statistics on vulnerability types, exploitation status,
    and CVSS scores.

    Original Python version Copyright (C) 2021 Kevin Breen, Immersive Labs
    https://github.com/Immersive-Labs-Sec/msrc-api

    PowerShell port by Fabian Bader

.PARAMETER SecurityUpdate
    Date string for the report query in format YYYY-MMM (e.g., 2024-Oct)

.PARAMETER CVELink
    Choose the CVE link format for output, either "MSRC", "CVE.org", or "None". Default is "MSRC".
    - "MSRC": Links to Microsoft's update guide (https://msrc.microsoft.com/update-guide/vulnerability/)
    - "CVE.org": Links to the CVE.org record (https://www.cve.org/CVERecord?id=)
    - "None": No CVE links in the human readable output

.PARAMETER BaseScore
    Base CVSS score threshold for highlighting high-severity vulnerabilities. Default is 8.0
    Vulnerabilities with a CVSS score equal to or greater than this value will be highlighted in the output.

.PARAMETER Output
    Output format: "human-readable" (default), "json", or "psobject".
    - "human-readable": Outputs a formatted text report to the console.
    - "json": Outputs the data in JSON format.
    - "psobject": Outputs the data as PowerShell objects for further processing.

.PARAMETER IncludeCriticality
    Include vulnerability criticality in the output (e.g., Critical, Important, Moderate, Low).
    This will also highlight vulnerabilities with Critical rating as high-severity regardless of CVSS score.

.PARAMETER IncludeCustomerActionRequired
    Include information about whether customer action is required for each vulnerability.
    In the human-readable output, vulnerabilities that do not require customer action will be marked as [FIXED].

.EXAMPLE
    .\patch_review.ps1 -SecurityUpdate "2025-Oct"

.NOTES
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

[CmdletBinding()]
param(
    [Alias("SecurityUpdate")]
    [Parameter(Position = 0, HelpMessage = "Date string for the report query in format YYYY-MMM or YYYY-MM")]
    [string]$ReportDate,

    [ValidateSet("MSRC", "CVE.org", "None")]
    [string]$CVELink = "MSRC",

    [float]$BaseScore = 8.0,

    [ValidateSet("human-readable", "json", "psobject")]
    [string]$Output = "human-readable",

    [switch]$IncludeCriticality,

    [switch]$IncludeCustomerActionRequired

)

$ErrorActionPreference = 'Stop'

# Configuration
$BaseUrl = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
$Headers = @{
    'Accept' = 'application/json'
}

$CVELinkUris = @{
    "MSRC"    = "https://msrc.microsoft.com/update-guide/vulnerability/"
    "CVE.org" = "https://www.cve.org/CVERecord?id="
}
if ($CVELink -eq "None") {
    $CVELinkUri = $CVELinkUris["MSRC"]
} else {
    $CVELinkUri = $CVELinkUris[$CVELink]
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

function ConvertTo-MonthName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthNumber
    )

    $MonthNames = @{
        '01' = 'Jan'
        '02' = 'Feb'
        '03' = 'Mar'
        '04' = 'Apr'
        '05' = 'May'
        '06' = 'Jun'
        '07' = 'Jul'
        '08' = 'Aug'
        '09' = 'Sep'
        '10' = 'Oct'
        '11' = 'Nov'
        '12' = 'Dec'
    }

    return $MonthNames[$MonthNumber]
}

function Write-Header {
    param(
        [string]$Title
    )

    Write-Host "[+] Microsoft Patch Tuesday Stats" -ForegroundColor Green
    Write-Host "[+] https://github.com/f-bader/msrc-api-ps" -ForegroundColor Green
    Write-Host "[+] $Title" -ForegroundColor Green
}

function Get-VulnerabilityCountByType {
    param(
        [string]$SearchType,
        [array]$AllVulns
    )

    $Counter = 0

    foreach ($Vuln in $AllVulns) {
        foreach ($Threat in $Vuln.Threats) {
            if ($Threat.Type -eq 0) {
                if ($SearchType -eq "Edge - Chromium") {
                    if ($Threat.ProductID[0] -eq '11655') {
                        $Counter++
                        break
                    }
                } elseif ($Threat.Description.Value -eq $SearchType) {
                    if ($Threat.ProductID[0] -eq '11655') {
                        # Do not double count Chromium Vulns
                        break
                    }
                    $Counter++
                    break
                }
            }
        }
    }

    return $Counter
}

function Get-ExploitedVulnerabilities {
    param(
        [array]$AllVulns
    )

    foreach ($Vuln in $AllVulns) {
        foreach ($Threat in $Vuln.Threats) {
            if ($Threat.Type -eq 1) {
                $Description = $Threat.Description.Value
                if ($Description -match 'Exploited:Yes') {
                    @{
                        CVE       = $Vuln.CVE
                        Title     = $Vuln.Title.Value
                        Exploited = $true
                    }
                    break
                }
            }
        }
    }
}

function Get-VulnerabilityCriticality {
    param(
        [array]$AllVulns
    )

    $PossibleValues = @(
        "Critical",
        "Important",
        "Moderate",
        "Low"
    )
    foreach ($Vuln in $AllVulns) {
        $Threats = $Vuln.Threats | Where-Object { $_.Type -eq 3 }
        foreach ($Threat in $Threats) {
            $Description = $Threat.Description.Value -split ";" | Select-Object -Unique
            if ($PossibleValues -contains $Description) {
                @{
                    CVE         = $Vuln.CVE
                    Title       = $Vuln.Title.Value
                    Criticality = $Description
                }
                break
            }
        }
    }
}

function Get-ExploitedVulnerabilities {
    param(
        [array]$AllVulns
    )

    foreach ($Vuln in $AllVulns) {
        foreach ($Threat in $Vuln.Threats) {
            if ($Threat.Type -eq 1) {
                $Description = $Threat.Description.Value
                if ($Description -match 'Exploited:Yes') {
                    @{
                        CVE       = $Vuln.CVE
                        Title     = $Vuln.Title.Value
                        Exploited = $true
                    }
                    break
                }
            }
        }
    }
}

function Get-CustomerActionRequired {
    param(
        [array]$AllVulns
    )

    foreach ($Vuln in $AllVulns) {
        $CustomerActionRequired = $Vuln.Notes | Where-Object Title -eq "Customer Action Required" | Select-Object -ExpandProperty Value
        $CustomerActionRequiredBool = if ($CustomerActionRequired -eq "Yes") { $true } else { $false }
        [PSCustomObject]@{
            CVE                    = $Vuln.CVE
            Title                  = $Vuln.Title.Value
            CustomerActionRequired = $CustomerActionRequiredBool
        }
    }
}

function Get-PubliclyDisclosedVulnerabilities {
    param(
        [array]$AllVulns
    )

    foreach ($Vuln in $AllVulns) {
        $AssociatedThreatDescription = ($Vuln.Threats.Description.Value) -split ";" | Select-Object -Unique
        if ($AssociatedThreatDescription -contains 'Publicly Disclosed:Yes') {
            @{
                CVE               = $Vuln.CVE
                Title             = $Vuln.Title.Value
                PubliclyDisclosed = $true
            }
        }
    }
}

function Get-ExploitationLikely {
    param(
        [array]$AllVulns
    )

    foreach ($Vuln in $AllVulns) {
        foreach ($Threat in $Vuln.Threats) {
            if ($Threat.Type -eq 1) {
                $Description = $Threat.Description.Value
                if ($Description -match 'Exploitation More Likely') {
                    @{
                        CVE                    = $Vuln.CVE
                        Title                  = $Vuln.Title.Value
                        ExploitationMoreLikely = $true
                    }
                    break
                }
            }
        }
    }
}

function Format-CvssScore {
    param(
        [string]$Score,
        [int]$MaxLengthOfCVEScore = 4
    )
    # Force american number format with dot as decimal separator
    if ($Score -eq "n/a") {
        return $Score.PadLeft($MaxLengthOfCVEScore)
    } else {
        $CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture
        [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US")
        $FormattedScore = "{0:N1}" -f [float]$Score
        $FormattedScore = $FormattedScore.PadLeft($MaxLengthOfCVEScore)
        [System.Globalization.CultureInfo]::CurrentCulture = $CurrentCulture
    }
    return $FormattedScore
}

# Main script execution
try {
    if ([string]::IsNullOrWhiteSpace($ReportDate)) {
        # Set to current month if not provided, always use english month name
        $ReportDate = (Get-Date).ToString("yyyy-MMM", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    # Validate date format
    if ( $ReportDate -match '^\d{4}-\d{2}$' ) {
        $ReportMonth = $ReportDate -replace '^\d{4}-(\d{2})$', '$1'
        $ReportYear = $ReportDate -replace '^(\d{4})-\d{2}$', '$1'
        $MonthName = ConvertTo-MonthName -MonthNumber $ReportMonth
        $ReportDate = "$ReportYear-$MonthName"
    }
    if (-not ($ReportDate -match '^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')) {
        Write-Host "[!] Invalid date format. Please use 'YYYY-MMM' or 'YYYY-MM' (e.g., 2024-Oct or 2024-10) " -ForegroundColor Red
        exit 1
    }

    # Get the security release data
    Write-Verbose "Fetching data from MSRC API for $ReportDate"
    $Response = Invoke-RestMethod -Uri "$BaseUrl/cvrf/$ReportDate" -Headers $Headers -Method Get -ErrorAction Stop

    if ($null -eq $Response) {
        Write-Host "[!] No release notes found for $ReportDate" -ForegroundColor Red
        exit 1
    }

    # Extract data
    $Title = if ($Response.DocumentTitle.Value) { $Response.DocumentTitle.Value } else { 'Release not found' }
    if ( $null -eq $Response.Vulnerability ) {
        $AllVulns = @()
    } else {
        $AllVulns = $Response.Vulnerability
    }

    # Filter out entries with null or empty Title
    $AllVulns = $AllVulns | Where-Object { -not ( [string]::IsNullOrWhiteSpace($_.Title) ) }

    # Get exploited vulnerabilities
    $Exploited = Get-ExploitedVulnerabilities -AllVulns $AllVulns
    # Get exploitation likely vulnerabilities
    $Exploitation = Get-ExploitationLikely -AllVulns $AllVulns
    # Get publicly disclosed vulnerabilities
    $PubliclyDisclosed = Get-PubliclyDisclosedVulnerabilities -AllVulns $AllVulns
    # Get vulnerability criticality
    $VulnerabilityCriticality = Get-VulnerabilityCriticality -AllVulns $AllVulns
    # Get customer action required vulnerabilities
    $CustomerActionRequired = Get-CustomerActionRequired -AllVulns $AllVulns

    # Add new properties to the vulnerabilities for easier output formatting
    foreach ($Vuln in $AllVulns) {
        # Add property for exploited vulnerabilities
        $isExploited = $false
        foreach ($Expl in $Exploited) {
            if ($Vuln.CVE -eq $Expl.CVE) {
                $isExploited = $true
                break
            }
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "Exploited" -Value $isExploited -Force
        # Add property for exploitation likely vulnerabilities
        $isExploitationLikely = $false
        foreach ($Expl in $Exploitation) {
            if ($Vuln.CVE -eq $Expl.CVE) {
                $isExploitationLikely = $true
                break
            }
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "ExploitationLikely" -Value $isExploitationLikely -Force

        # Add URL property
        $Vuln | Add-Member -MemberType NoteProperty -Name "URL" -Value "$CVELinkUri$($Vuln.CVE)" -Force
        # Add property for publicly disclosed vulnerabilities
        $isPubliclyDisclosed = $false
        foreach ($Expl in $PubliclyDisclosed) {
            if ($Vuln.CVE -eq $Expl.CVE) {
                $isPubliclyDisclosed = $true
                break
            }
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "PubliclyDisclosed" -Value $isPubliclyDisclosed -Force

        # Set CvssScore property
        $CvssScore = "n/a"
        if ($null -ne $Vuln.CVSSScoreSets -and $Vuln.CVSSScoreSets.Count -gt 0) {
            $CvssScore = $Vuln.CVSSScoreSets[0].BaseScore
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "CvssScore" -Value $CvssScore -Force

        # Replace Title object with its value
        if ($null -ne $Vuln.Title) {
            $Vuln | Add-Member -MemberType NoteProperty -Name "Title" -Value $Vuln.Title.Value -Force
        } else {
            $Vuln | Add-Member -MemberType NoteProperty -Name "Title" -Value "N/A" -Force
        }

        # Add property for vulnerability criticality
        $Criticality = "N/A"
        foreach ($Crit in $VulnerabilityCriticality) {
            if ($Vuln.CVE -eq $Crit.CVE) {
                $Criticality = $Crit.Criticality
                break
            }
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "Criticality" -Value $Criticality -Force

        # Add property for highest rated vulnerabilities
        $isHighestRated = $false
        if ($CvssScore -ne "n/a") {
            if ( $IncludeCriticality -and $Criticality -eq "Critical" ) {
                $isHighestRated = $true
            }
            if ([float]$CvssScore -ge $BaseScore) {
                $isHighestRated = $true
            }
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "HighestRated" -Value $isHighestRated -Force

        # Add property for customer action required vulnerabilities
        $isCustomerActionRequired = $CustomerActionRequired | Where-Object { $_.CVE -eq $Vuln.CVE } | Select-Object -ExpandProperty CustomerActionRequired
        if ($null -eq $isCustomerActionRequired) {
            $isCustomerActionRequired = $false
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "CustomerActionRequired" -Value $isCustomerActionRequired -Force
    }

    $OutputData = $AllVulns | Select-Object CVE, Title, CvssScore, Criticality, Exploited, ExploitationLikely, CustomerActionRequired, HighestRated, PubliclyDisclosed, URL

    if ($Output -eq "psobject") {
        $OutputData
        exit 0
    }

    if ($Output -eq "json") {
        $OutputData | ConvertTo-Json -Depth 3
        exit 0
    }

    if ($Output -eq "human-readable") {
        # Human readable output

        # Display header
        Write-Header -Title $Title

        # Display total vulnerabilities
        Write-Host "[+] Found a total of $($AllVulns.Count) vulnerabilities" -ForegroundColor Green

        # Count vulnerabilities by type
        foreach ($VulnType in $VulnTypes) {
            $Count = Get-VulnerabilityCountByType -SearchType $VulnType -AllVulns $AllVulns
            Write-Host "  [-] $Count $VulnType Vulnerabilities" -ForegroundColor Cyan
        }

        $MaxLengthOfCVE = $AllVulns.CVE | Measure-Object -Property Length -Maximum | Select-Object -ExpandProperty Maximum
        $MaxCVEScore = $AllVulns.CvssScore | Where-Object { $_ -ne "n/a" } | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
        $MaxLengthOfCriticality = $AllVulns.Criticality | Where-Object { $_ -ne "N/A" } | Measure-Object -Property Length -Maximum | Select-Object -ExpandProperty Maximum
        if ( $MaxCVEScore -eq 10 ) {
            $MaxLengthOfCVEScore = 4
        } else {
            $MaxLengthOfCVEScore = 3
        }

        # Display exploited vulnerabilities
        $Exploited = $AllVulns | Where-Object { $_.Exploited -eq $true } | Sort-Object -Property @{Expression = "CvssScore"; Descending = $true }, @{Expression = "Title"; Descending = $false }
        Write-Host "[+] Found $($Exploited.Count) exploited in the wild" -ForegroundColor Green
        foreach ($CVE in $Exploited) {
            $FormattedScore = Format-CvssScore -Score $CVE.CvssScore -MaxLengthOfCVEScore $MaxLengthOfCVEScore
            $CriticalityText = ""
            if ($IncludeCriticality) {
                $CriticalityText = " - $($CVE.Criticality.PadRight($MaxLengthOfCriticality))"
            }
            Write-Host "  [-] $($CVE.CVE.PadRight($MaxLengthOfCVE)) - $FormattedScore$($CriticalityText) - $($CVE.Title)" -ForegroundColor Red -NoNewline
            if ($IncludeCustomerActionRequired) {
                if (-not $CVE.CustomerActionRequired) {
                    Write-Host " [FIXED]" -ForegroundColor Green
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        }

        # Display publicly disclosed vulnerabilities
        $PubliclyDisclosed = $AllVulns | Where-Object { $_.PubliclyDisclosed -eq $true } | Sort-Object -Property CvssScore -Descending
        Write-Host "[+] Found $($PubliclyDisclosed.Count) already publicly disclosed vulnerabilities" -ForegroundColor Green
        foreach ($CVE in $PubliclyDisclosed) {
            $FormattedScore = Format-CvssScore -Score $CVE.CvssScore -MaxLengthOfCVEScore $MaxLengthOfCVEScore
            $CriticalityText = ""
            if ($IncludeCriticality) {
                $CriticalityText = " - $($CVE.Criticality.PadRight($MaxLengthOfCriticality))"
            }
            Write-Host "  [-] $($CVE.CVE.PadRight($MaxLengthOfCVE)) - $FormattedScore$($CriticalityText) - $($CVE.Title)" -ForegroundColor Red -NoNewline
            if ($IncludeCustomerActionRequired) {
                if (-not $CVE.CustomerActionRequired) {
                    Write-Host " [FIXED]" -ForegroundColor Green
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        }

        # Display highest rated vulnerabilities
        $HighestRated = $AllVulns | Where-Object { $_.HighestRated -eq $true } | Sort-Object -Property CvssScore -Descending
        if ( $IncludeCriticality ) {
            Write-Host "[+] Highest Rated Vulnerabilities - CVE >= $BaseScore or Critical" -ForegroundColor Green
        } else {
            Write-Host "[+] Highest Rated Vulnerabilities - CVE >= $BaseScore" -ForegroundColor Green
        }
        foreach ($CVE in $HighestRated) {
            $FormattedScore = Format-CvssScore -Score $CVE.CvssScore -MaxLengthOfCVEScore $MaxLengthOfCVEScore
            $CriticalityText = ""
            if ($IncludeCriticality) {
                $CriticalityText = " - $($CVE.Criticality.PadRight($MaxLengthOfCriticality))"
            }
            Write-Host "  [-] $($CVE.CVE.PadRight($MaxLengthOfCVE)) - $FormattedScore$($CriticalityText) - $($CVE.Title)" -ForegroundColor Yellow -NoNewline
            if ($IncludeCustomerActionRequired) {
                if (-not $CVE.CustomerActionRequired) {
                    Write-Host " [FIXED]" -ForegroundColor Green
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        }

        # Display exploitation likely vulnerabilities
        $Exploitation = $AllVulns | Where-Object { $_.ExploitationLikely -eq $true } | Sort-Object -Property CvssScore -Descending
        Write-Host "[+] Found $($Exploitation.Count) vulnerabilities more likely to be exploited" -ForegroundColor Green
        foreach ($CVE in $Exploitation) {
            $FormattedScore = Format-CvssScore -Score $CVE.CvssScore -MaxLengthOfCVEScore $MaxLengthOfCVEScore
            if ($CVELink -eq "None") {
                $CVELinkText = ""
            } else {
                $CVELinkText = " - $($CVELinkUri)$($CVE.CVE)"
            }
            if ($IncludeCriticality) {
                Write-Host "  [-] $($CVE.CVE.PadRight($MaxLengthOfCVE)) - $FormattedScore - $($CVE.Criticality.PadRight($MaxLengthOfCriticality)) - $($CVE.Title)$($CVELinkText)" -ForegroundColor Yellow
            } else {
                Write-Host "  [-] $($CVE.CVE.PadRight($MaxLengthOfCVE)) - $FormattedScore - $($CVE.Title)$($CVELinkText)" -ForegroundColor Yellow
            }
        }
    }
} catch {
    if ($_.Exception.Response.StatusCode) {
        $StatusCode = [int]$_.Exception.Response.StatusCode
        Write-Host "[!] That's a $StatusCode from MS - no release notes yet" -ForegroundColor Red
    } else {
        Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}
