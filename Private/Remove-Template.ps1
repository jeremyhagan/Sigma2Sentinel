function Remove-Template {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Object]
        $Template
    )
    $contentId = $template.name
    Write-Output "Removing rule template: $($template.properties.displayName)"
    try {
        Invoke-RestMethod -Method Delete -Headers @{Authorization="Bearer $((Get-AzAccessToken).Token)"} `
            -Uri ($uriStem + "/contenttemplates/$($contentId)?api-version=2023-11-01") | Out-Null
    }
    catch {
        Write-Error "StatusCode:" $_.Exception.Response.StatusCode.value__
        Write-Error "StatusDescription:" $_.Exception.Response.StatusDescription
        Write-Error "Failed to remove template: $($template.properties.displayName)"
    }
}
