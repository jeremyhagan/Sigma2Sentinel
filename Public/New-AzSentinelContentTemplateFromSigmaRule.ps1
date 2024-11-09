[CmdletBinding(DefaultParameterSetName='ByPathString')]
param (
    # Parameter help description
    [Parameter(Mandatory, ParameterSetName='ByFileObject')]
    [System.IO.FileInfo]
    $File,
    # The path under which the sigma yaml files exist, or the path to a single yaml file
    [Parameter(Mandatory, ParameterSetName='ByPathString')]
    [string]$Path,
    # The Sentinel Workspace name
    [Parameter(Mandatory)]
    [string]$WorkspaceName,
    # The Azure Resource Group the workspace is in 
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,
    # Subscription GUID
    [Parameter(Mandatory)]
    [string]$SubscriptionId,
    # The sigma backend to use. Currently only supports microsoft365defender
    [Parameter()]
    [string]
    $SigmaBackend = "microsoft_defender",
    # The source name disaplyed in the list of rule templates in Sentinel. EG: SigmaHQ
    [Parameter()]
    [string]
    $SourceName = "Sigma Rule",
    # The source URL link if any related to the source name. Will be displayed in the rule properties
    [Parameter()]
    [string]
    $SourceUrl
)
#Requires -modules powershell-yaml,Az.Accounts,Az.SecurityInsights,AzExpression
#Requires -PSEdition Core
#region Global Variables
$supportedCategories = @(
    "process_creation",
    "image_load",
    "network_connection",
    "file_access",
    "file_change",
    "file_delete",
    "file_event",
    "file_rename"
    "registry_add",
    "registry_delete",
    "registry_event",
    "registry_set"
)
$uriStem = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups"
$uriStem += "/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces"
$uriStem += "/$WorkspaceName/providers/Microsoft.SecurityInsights"
$headers = @{Authorization="Bearer $((Get-AzAccessToken).Token)"}
#endregion

#region main
# Get all existing detection rules
$CurrentTemplates = Invoke-RestMethod -Method GET -Uri ($uriStem + "/contentTemplates?api-version=2024-03-01") `
    -Headers $headers

# if the Path variable was supplied, then get a handle on the file.
if ($Path) {
    $File = Get-Item $Path -ErrorAction:Stop
}

# Assume the sigma rule is already present and doesn't need updating
$addRuleToSentinel = $false
$yaml = ConvertFrom-Yaml (Get-Content $File -raw)
# Only process the rules types applicable to the microsoft_defender backend
if ($yaml.logsource.product -eq "windows" -and 
    $supportedCategories -contains $yaml.logsource.category
) {
    Write-Verbose "$($File.Name) is supported by sigma engine. Proecessing"
    
    # Determine if this is a rule we already have in Sentinel
    if ($CurrentTemplates.value.name -contains $yaml.id) {
        # if we get here then the rule already exists, so we need to determine if it needs updating
        Write-Verbose "Sigma rule $($yaml.title) already exists. Checking for updates."
        $existingTemplate = $CurrentTemplates.value | Where-Object {$_.name -eq $yaml.id}
        $existingVersion = [version]$existingTemplate.properties.version
        
        if ($null -eq $existingTemplate.properties.lastPublishDate -and $null -ne $yaml.modified) {
            Write-Verbose "Sigma rule was updated on $($yaml.modified) and the existing template has never been updated."
            $addRuleToSentinel = $true
            $version = [version]::New(
                $existingVersion.Major, $existingVersion.Minor, $existingVersion.Build + 1).ToString()
        }
        if ($null -ne $yaml.modified -and 
            (Get-Date $yaml.modified) -gt (Get-Date $existingTemplate.properties.lastPublishDate))
        {
            Write-Verbose "The Sigma rule modified date is newer than the Sentinel template lastModified date."
            $action = "Updated"
            $addRuleToSentinel = $true
            $version = [version]::New(
                $existingVersion.Major, $existingVersion.Minor, $existingVersion.Build + 1).ToString()
        }
    } else
    {
        # if we get here then then rule is new and so we will be adding it
        Write-Verbose "Sigma rule `"$($yaml.title)`" does not exist in Sentinel. Adding..."
        $action = "Added"
        $addRuleToSentinel = $true
        $version = '1.0.0'
    }
    if ($addRuleToSentinel)
    {
        # Preprocess any parameters which need it
        $query = sigma.exe convert -t $SigmaBackend -f default $File.FullName
        if ($null -ne $query)
        {
            $query = $query -join "`n"
            $severity = New-Severity -SigmaYaml $yaml
            $description = New-Description -SigmaYaml $yaml
            $tactics = Read-Tactics -SigmaYaml $yaml
            $techniques = Read-Techniques -SigmaYaml $yaml
            
            # Process items which are specific to the chosen sigma backend. Specifically the entity mapping and the data sources
            $table = ($query -split '\|')[0].Trim()
            switch ($SigmaBackend) {
                'microsoft_defender' {
                    $requiredDataConnectors = @(@{connectorId = 'MicrosoftThreatProtection'; dataTypes = @($table)})
                    $query += (Update-QueryWithEntityMappingColumns -TableName $table)
                    $entityMappings = New-EntityMappings -TableName $table
                }
                Default {}
            }

            # Build the parameters for the ARM template creation
            $ArmParams = @{
                Version = $version;
                Name = $yaml.id;
                Description = $description;
                DisplayName = $yaml.title;
                Query = $query;
                Severity = $severity;
                SourceType = @{kind="LocalWorkspace";name=$SourceName};
            }
            
            # Build the parameters for the API call.
            $ApiParams = @{
                WorkspaceName = $WorkspaceName;
                ResourceGroupName = $ResourceGroupName;
                SubscriptionId = $SubscriptionId;
                SourceName = $SourceName;
                Version = $version;
                ContentId = $yaml.id;
                DisplayName = $yaml.title;
                SourceUrl = $SourceUrl;
            }

            # Add optional parameters for both ARM and API
            if ($null -ne $yaml.author) {
                $ApiParams.Add('Author', @{'name' = $yaml.author})
                $ArmParams.Add('Author', @{'name' = $yaml.author})
            }
            if ($tactics.count -gt 0) {
                $ApiParams.Add('Tactics', $tactics)
                $ArmParams.Add('Tactics', $tactics)
            }
            if ($techniques.count -gt 0) {
                $ApiParams.Add('Techniques', $techniques)
                $ArmParams.Add('Techniques', $techniques)
            }
            if ($null -ne $yaml.date) {$ApiParams.Add('FirstPublishDate', ($yaml.date -replace "/","-"))}
            if ($null -ne $yaml.modified) {$ApiParams.Add('LastPublishDate', ($yaml.modified -replace "/","-"))}
            if ($null -ne $requiredDataConnectors) {$ArmParams.Add('RequiredDataConnectors', $requiredDataConnectors)}
            if ($null -ne $entityMappings) {$ArmParams.Add('EntityMappings', $entityMappings)}

            $armTemplate = Build-AzSetinelAlertRuleTemplateArmDocument @ArmParams
            $ApiParams.Add('ArmTemplate', $armTemplate)
            
            try {
                $response = Set-AzSentinelContentTemplate @ApiParams
                Write-Verbose $response
                Write-Output "$Action content template: $($ApiParams.DisplayName)."
                
            }
            catch {
                $exception = $_
                Write-Error "Failed to create rule template."
                Throw $exception
            }
        }
        else
        {
            Write-Warning "Failed to generate query from sigma rule. See previous error thrown by sigma CLI"
            Throw "Invalid Sigma"
        }
    }
    else
    {
        Write-Output "$($yaml.title) is already in Sentinel and has not been updated."
    }
    <#
    if ($CurrentTemplates.value.name -contains $yaml.id)
    {
        # if we get here then there is already a rule with this contentId. 
        # Maybe in the futurethere will be a GUID clash because of the moron creating the sigma
        # rule. At present this is problem for future Jeremy.
        $template = $CurrentTemplates.value | Where-Object {$_.name -eq $contentId}
        # Get the full template which includes the ARM template
        $template = (Invoke-RestMethod  -Proxy http://forti-proxy.dmzmgmt.govt:8080 `
            -Method Get -Headers $headers `
            -Uri ("https://management.azure.com" + $template.id + "?api-version=2023-11-01"))
        $templateDescription = $template.properties.mainTemplate.resources[0].properties.description
    
    }
#>
}
else
{
    Write-Warning "$($File.Name) is NOT supported by sigma engine. Unsupported category is $($yaml.logsource.category)"
}
#endregion main
