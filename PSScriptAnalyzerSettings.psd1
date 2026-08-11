@{
    ExcludeRules = @(
        # Write-Host is intentional in the colorized human-readable CLI renderer.
        'PSAvoidUsingWriteHost'
    )
}
