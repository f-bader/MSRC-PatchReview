BeforeAll {
    . "$PSScriptRoot/../patch_review.ps1"
    $fixture = Get-Content -Raw "$PSScriptRoot/fixtures/sample-cvrf.json" | ConvertFrom-Json
    $report = ConvertFrom-CvrfDocument -Document $fixture -ScoreThreshold 8.0 -UseCriticality $true -LinkUri $null
}

Describe 'ConvertFrom-CvrfDocument' {
    It 'normalizes every non-empty vulnerability in one record' {
        $report.Records.Count | Should -Be 3
        $report.TypeCounts['Remote Code Execution'] | Should -Be 1
        $report.TypeCounts['Edge - Chromium'] | Should -Be 1
        $report.TypeCounts['Elevation of Privilege'] | Should -Be 1
    }

    It 'includes Critical vulnerabilities without CVSS in the highest-rated set' {
        $critical = $report.Records | Where-Object CVE -eq 'CVE-TEST-0001'
        $critical.CvssScore | Should -Be 'n/a'
        $critical.Criticality | Should -Be 'Critical'
        $critical.HighestRated | Should -BeTrue
    }

    It 'sorts numeric CVSS values before missing values' {
        $sorted = Get-SortedVulnerabilities $report.Records
        @($sorted.CVE) | Should -Be @('CVE-TEST-0003', 'CVE-TEST-0002', 'CVE-TEST-0001')
        (Format-CvssScore -Score ($sorted[1].SortScore)).Trim() | Should -Be '9.8'
    }

    It 'honors disabled CVE links in normalized and Markdown output' {
        @($report.Records.URL | Where-Object { $_ }).Count | Should -Be 0
        $markdown = @(Write-MarkdownReport $report) -join "`n"
        $markdown | Should -Not -Match '\]\(https?://'
        $markdown | Should -Match 'Critical no-score \\| title'
        $markdown | Should -Match '\| CVE-TEST-0002 \| 9\.8 \|'
    }
}

Describe 'Invoke-PatchReview output modes' {
    BeforeEach {
        Mock Invoke-RestMethod { $fixture }
        Mock Write-Host {}
    }

    It 'emits PowerShell objects end to end' {
        $output = @(Invoke-PatchReview '2025-05' 'None' 8 'psobject' $true $true)
        $output.Count | Should -Be 3
        $output[0].PSObject.Properties.Name | Should -Not -Contain 'SortScore'
    }

    It 'emits valid JSON end to end' {
        $json = Invoke-PatchReview '2025-05' 'MSRC' 8 'json' $true $true
        @($json | ConvertFrom-Json).Count | Should -Be 3
    }

    It 'renders Markdown and the human report end to end' {
        $markdown = @(Invoke-PatchReview '2025-05' 'None' 8 'markdown' $true $true) -join "`n"
        $markdown | Should -Match '# Sample Patch Tuesday'
        { Invoke-PatchReview '2025-05' 'MSRC' 8 'human-readable' $true $true } | Should -Not -Throw
    }
}
