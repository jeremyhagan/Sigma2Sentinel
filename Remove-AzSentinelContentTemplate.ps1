<#
    .SYNOPSIS
    Delete user defined Sentinel Alert Rule Templates from a workspace.
    
    .DESCRIPTION
    When run without any parameters, will prompt which template to remove.
    When run with the -All switch ALL templates will be removed.
    When run with a DisplayName only that template will be removed.
	
    .PARAMETER WorkspaceName
    The name of the Azure Log Analytics workspace containing the rule(s) to connect to.
    .PARAMETER ResourceGroupName
    The name of the Resource Group containing the workspace
    .PARAMETER SubscriptionId
    The name of the Azure subscription continaing the workspace
    .PARAMETER All
    If supplied, all user-defined rule template will be deleted.
    .PARAMETER DisplayName
    The DisplayName of the template to remove.
    	
    .EXAMPLE
    Remove-AzSentinelContentTemplate.ps1 -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -SubscriptionId "SubscriptionId"
    The example above will prompt for a rule to delete.
    OUTPUT
    [1]: HackTool - Potential Impacket Lateral Movement Activity
    [2]: New Port Forwarding Rule Added Via Netsh.EXE
    Please select a rule template to delete:
    .EXAMPLE
    PS> Remove-AzSentinelContentTemplate.ps1 -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -SubscriptionId "SubscriptionId" -All
    The example above will remove all temaplates. Use -Confirm:$false to avoid being prompted
    .EXAMPLE
    PS> Remove-AzSentinelContentTemplate.ps1 -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -SubscriptionId "SubscriptionId" -DisplayName "MyRuleName"
    The exmample above will remove the specified rule template if it exists.
    #>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param (
    # The Sentinel Workspace name
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceName,
    # The Azure Resource Group the workspace is in 
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    # Subscription GUID
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    # Delete all switch
    [Parameter(Mandatory=$false)]
    [switch]
    $All = $false,
    # Display Name of the template to remove
    [Parameter(Mandatory=$false)]
    [string]
    $DisplayName
)
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

$uriStem = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups"
$uriStem += "/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces"
$uriStem += "/$WorkspaceName/providers/Microsoft.SecurityInsights"
if ($null -eq (Get-AzAccessToken -ErrorAction:SilentlyContinue) -or (Get-AzAccessToken).ExpiresOn -lt (Get-Date)) {
            Write-Error "You must call Connect-AzAccount to acquire an access token before using the function."
            Throw "Not logged in."
}
$headers = @{Authorization="Bearer $((Get-AzAccessToken).Token)"}
try {
    $CurrentTemplates = Invoke-RestMethod -Method GET -Uri ($uriStem + "/contentTemplates?api-version=2023-11-01") `
        -Headers $headers
}
catch {
    Write-Error "Failed to retrieve any templates"
    Throw $_.Exception
}
if ($CurrentTemplates.value.Count -eq 0) {
    Write-Warning "There are no user-created templates in the workspace specified."
    Exit 0
}

if ($all) {
    if ($PSCmdlet.ShouldProcess(
            ("Removing $($CurrentTemplates.value.count) rule templates"),
            ("Would you like to remove $($CurrentTemplates.value.count) rule templates?"),
            "Remove All templates prompt"
        )
    ) {
        foreach ($template in ($CurrentTemplates.value)) {
            Remove-Template -Template $template
        }
    }
}
elseif ("" -ne $DisplayName) {
    if ($CurrentTemplates.value.properties.displayName -contains $DisplayName) {
        $template = $CurrentTemplates.value | Where-Object {$_.properties.displayName -eq $DisplayName}
        Remove-Template -Template $template
    }
    else {
        Write-Warning "Template `"$($template.properties.displayName)`" not found!!"
    }
}
else {
    $output = @()
    for ($i = 0; $i -lt $CurrentTemplates.value.count; $i++) {
        $output += "[$($i+1)]: $($CurrentTemplates.value[$i].properties.displayName)"
    }
    Write-Output $output
    $selection = (Read-Host "Please select a rule template to delete") - 1
    Remove-Template -Template $CurrentTemplates.value[$selection]
}