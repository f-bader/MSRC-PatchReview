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
    
.EXAMPLE
    .\patch_review.ps1 -SecurityUpdate "2024-Oct"
    
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

    [ValidateSet("MSRC", "CVE.org")]
    [string]$CVELink = "MSRC",

    [float]$BaseScore = 8.0,

    [ValidateSet("human-readable", "json", "psobject")]
    [string]$Output = "human-readable"

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
$CVELinkUri = $CVELinkUris[$CVELink]

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
        $CvssScore = 0.0
        $CvssSets = $Vuln.CVSSScoreSets
        
        if ($null -ne $CvssSets -and $CvssSets.Count -gt 0) {
            $CvssScore = $CvssSets[0].BaseScore
            if ($null -eq $CvssScore) {
                $CvssScore = 0.0
            }
        }
        
        foreach ($Threat in $Vuln.Threats) {
            if ($Threat.Type -eq 1) {
                $Description = $Threat.Description.Value
                if ($Description -match 'Exploited:Yes') {
                    @{
                        CVE       = $Vuln.CVE
                        CvssScore = $CvssScore
                        Title     = $Vuln.Title.Value
                        Exploited = $true
                    }
                    break
                }
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
                        CvssScore              = $Vuln.CVSSScoreSets[0].BaseScore
                        Title                  = $Vuln.Title.Value
                        ExploitationMoreLikely = $true
                    }
                    break
                }
            }
        }
    }
}

function Get-HighestRatedVulnerabilities {
    param(
        [array]$AllVulns,
        [float]$BaseScore = 8.0
    )
    
    foreach ($Vuln in $AllVulns) {
        $CvssScore = 0.0
        $CvssSets = $Vuln.CVSSScoreSets
        
        if ($null -ne $CvssSets -and $CvssSets.Count -gt 0) {
            $CvssScore = $CvssSets[0].BaseScore
            if ($null -eq $CvssScore) {
                $CvssScore = 0.0
            }
        }
        
        if ($CvssScore -ge $BaseScore) {
            @{
                CVE       = $Vuln.CVE
                CvssScore = $CvssScore
                Title     = $Vuln.Title.Value
            }
        }
    }
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
    $AllVulns = $AllVulns | where { -not ( [string]::IsNullOrWhiteSpace($_.Title) ) }

    # Get exploited vulnerabilities
    $Exploited = Get-ExploitedVulnerabilities -AllVulns $AllVulns
    # Get exploitation likely vulnerabilities
    $Exploitation = Get-ExploitationLikely -AllVulns $AllVulns
    # Get highest rated vulnerabilities
    $HighestRated = Get-HighestRatedVulnerabilities -AllVulns $AllVulns -BaseScore $BaseScore

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
        $isHighestRated = $false
        foreach ($Expl in $HighestRated) {
            if ($Vuln.CVE -eq $Expl.CVE) {
                $isHighestRated = $true
                break
            }
        }
        $Vuln | Add-Member -MemberType NoteProperty -Name "HighestRated" -Value $isHighestRated -Force
        # Add URL property
        $Vuln | Add-Member -MemberType NoteProperty -Name "URL" -Value "$CVELinkUri$($Vuln.CVE)" -Force
    }

    $OutputData = $AllVulns | Select-Object CVE, @{Name = "Title"; Expression = { $_.Title.Value } }, @{Name = "CvssScore"; Expression = { if ($null -ne $_.CVSSScoreSets -and $_.CVSSScoreSets.Count -gt 0) { $_.CVSSScoreSets[0].BaseScore } else { $null } } }, Exploited, ExploitationLikely, HighestRated, URL
    
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
    
        # Display exploited vulnerabilities
        Write-Host "[+] Found $($Exploited.Count) exploited in the wild" -ForegroundColor Green
        foreach ($CVE in $Exploited) {
            Write-Host "  [-] $($CVE.CVE) - $($CVE.CvssScore) - $($CVE.Title)" -ForegroundColor Red
        }
    
        # Display highest rated vulnerabilities
        Write-Host "[+] Highest Rated Vulnerabilities - CVE >= $BaseScore" -ForegroundColor Green
        foreach ($CVE in $HighestRated) {
            if ($null -eq $CVE.CvssScore) {
                $CVE.CvssScore = "N/A"
            }
            Write-Host "  [-] $($CVE.CVE) - $($CVE.CvssScore) - $($CVE.Title)" -ForegroundColor Yellow
        }
    
    
        # Display exploitation likely vulnerabilities
        Write-Host "[+] Found $($Exploitation.Count) vulnerabilities more likely to be exploited" -ForegroundColor Green
        foreach ($CVE in $Exploitation) {
            if ($null -eq $CVE.CvssScore) {
                $CVE.CvssScore = "N/A"
            }
            Write-Host "  [-] $($CVE.CVE) - $($CVE.CvssScore) - $($CVELinkUri)$($CVE.CVE)" -ForegroundColor Yellow
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
