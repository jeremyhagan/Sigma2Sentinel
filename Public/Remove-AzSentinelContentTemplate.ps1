function Remove-AzSentinelContentTemplate {
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
        Remove-AzSentinelContentTemplate -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -SubscriptionId "SubscriptionId"
        The example above will prompt for a rule to delete.
        OUTPUT
        [1]: HackTool - Potential Impacket Lateral Movement Activity
        [2]: New Port Forwarding Rule Added Via Netsh.EXE
        Please select a rule template to delete:
        .EXAMPLE
        PS> Remove-AzSentinelContentTemplate -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -SubscriptionId "SubscriptionId" -All
        The example above will remove all templates. Use -Confirm:$false to avoid being prompted
        .EXAMPLE
        PS> Remove-AzSentinelContentTemplate -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -SubscriptionId "SubscriptionId" -DisplayName "MyRuleName"
        The example above will remove the specified rule template if it exists.
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        # The Sentinel Workspace name
        [Parameter(Mandatory=$true)]
        [string]
        $WorkspaceName,
        # The Azure Resource Group the workspace is in
        [Parameter(Mandatory=$true)]
        [string]
        $ResourceGroupName,
        # Subscription GUID
        [Parameter()]
        [string]
        $SubscriptionId,
        # Delete all switch
        [Parameter(Mandatory=$false)]
        [switch]
        $All = $false,
        # Display Name of the template to remove
        [Parameter(Mandatory=$false)]
        [string]
        $DisplayName
    )

    $Token = Get-AzAccessToken -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($null -eq $Token -or $Token.ExpiresOn -lt (Get-Date)) {
        Write-Warning "Access token is null or expired. Please log in with Connect-AzAccount"
        Throw "Not logged in."
    }
    if ([string]::IsNullOrEmpty($SubscriptionId)) {
        try {
            $SubscriptionId = (Get-AzContext).Subscription.Id
        }
        catch {
            Throw "Unable to determinie Subscription Id from Context. Please supply a valid subscription"
        }
    } else {
        try {
            Set-AzContext -Subscription $SubscriptionId
        }
        catch {
            Throw "The supplied subscription ID is not a valid subscription for the currently logged in user"
        }
    }
    $uriStem = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups"
    $uriStem += "/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces"
    $uriStem += "/$WorkspaceName/providers/Microsoft.SecurityInsights"

    $headers = @{Authorization="Bearer $($Token.Token)"}
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
        return
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
}