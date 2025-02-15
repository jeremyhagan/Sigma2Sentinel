function Set-AzSentinelContentTemplate {
    [CmdletBinding()]
    param (
        # The Sentinel Workspace name
        [Parameter(Mandatory)]
        [string]$WorkspaceName,
        # The Azure Resource Group the workspace is in
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        # Subscription name
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        # The content ID in the form of a GUID
        [Parameter(Mandatory)]
        [guid]
        $ContentId,
        # The display name of the rule template
        [Parameter(Mandatory)]
        [string]
        $DisplayName,
        # The source name of the analytics rule. This will show up as a filter in the web GUI
        [Parameter(Mandatory)]
        [string]
        $SourceName,
        # The main ARM template which contains the actual analytics rule
        [Parameter(Mandatory)]
        [hashtable]
        $ArmTemplate,
        # The version of the rule, if not provided defaults to 1.0.0
        [Parameter()]
        [string]
        $Version = "1.0.0",
        # The author of the rule. A hash containing any of email, link, name. EG: @{email=me@example.com;link="https://my.blog.com";name="Joe Blogs"}
        [Parameter()]
        [hashtable]
        $Author,
        # Source URL of where the rule came from. Usually a link to a sigma rule or some other repo
        [Parameter()]
        [string]
        $SourceUrl,
        # The MITRE ATT&CK framework tactics that apply to this rule
        [Parameter()]
        [array]
        $Tactics,
        # The MITRE ATT&CK framework techniques that apply to this rule
        [Parameter()]
        [array]
        $Techniques,
        # The first published date
        [Parameter()]
        [string]
        $FirstPublishDate,
        # The last published date
        [Parameter()]
        [string]
        $LastPublishDate
    )
    #region variables
    $apiVersion = '?api-version=2023-11-01'
    $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups"
    $uri += "/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces"
    $uri += "/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$($ContentId)$($apiVersion)"
    $contentKind = "AnalyticsRule"
    if ($PSVersionTable.PSEdition -eq "Core") {
        $uniqueString = New-AzUniqueString "$ContentId-$contentKind-$ContentId-$Version"
    }
    else {
        $uniqueString = (pwsh.exe -command {New-AzUniqueString "$ContentId-$contentKind-$ContentId-$Version"})
    }

    $contentProductId = "$ContentId-ar-$uniqueString"
    Write-Verbose "Content product Id = $contentProductId"
    $source = @{kind = "LocalWorkspace"; name = $SourceName}
    $contentSchemaVersion = '3.0.0'
    $packageKind = 'Standalone'

    # Build the request body
    $body = @{
        "properties" = @{
            "contentId"             = $ContentId
            "contentProductId"      = $contentProductId
            "displayName"           = $DisplayName
            "contentKind"           = $contentKind
            "version"               = $Version
            "packageId"             = $ContentId
            "packageVersion"        = $Version
            "contentSchemaVersion"  = $contentSchemaVersion
            "packageKind"           = $packageKind
            "source"                = $source
            "mainTemplate"          = $ArmTemplate
        }
    }
    if ($null -ne $Author) {$body.properties.Add("author", $author)}
    if ($null -ne $SourceUrl) {$body.properties.Add("support",@{tier = "Community"; name = "Community"; link = $SourceUrl})}
    if ($null -ne $Tactics) {$body.properties.Add('threatAnalysisTactics', $Tactics)}
    if ($null -ne $Techniques) {$body.properties.Add('threatAnalysisTechniques', $Techniques)}
    if ($null -ne $FirstPublishDate) {$body.properties.Add('firstPublishDate', $FirstPublishDate)}
    if ($null -ne $LastPublishDate) {$body.properties.Add('lastPublishDate', $LastPublishDate)}
    #endregion
    #region main
    try {
        $header = @{Authorization="Bearer $((Get-AzAccessToken).Token)"}
        Write-Verbose "Uri is: $uri"
        Write-Verbose "Request body is `n$(ConvertTo-Json $Body -Depth 20)"
        $response = Invoke-RestMethod -Method Put -Headers $header -Uri $uri -Body (
            ConvertTo-Json $Body -Depth 20 -EscapeHandling EscapeNonAscii) -ContentType "application/json"
    }
    catch {
        $exception = $_.Exception
        Write-Error "Caught exception"
        Write-Error $exception
        Write-Output "Rest method body has been copied to the clipboard."
        (ConvertTo-Json $Body -Depth 20) | clip
        Throw $exception
    }
    #endregion main
    return $response
}
