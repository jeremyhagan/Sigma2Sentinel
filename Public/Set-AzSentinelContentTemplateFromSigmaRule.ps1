function Set-AzSentinelContentTemplateFromSigmaRule {
    <#
        .SYNOPSIS
        Create a user defined Sentinel Alert Rule Template in a workspace.

        .DESCRIPTION
        Create a user defined Sentinel Alert Rule Template in a workspace from a supplied sigma rule.

        .PARAMETER File
        A File object returned by Get-Item. Used when running in a loop to create multiple rules
        .PARAMETER Path
        The path to a sigma YAML file
        .PARAMETER WorkspaceName
        The name of the Log Analytics workspace containing your Sentinel instance
        .PARAMETER ResourceGroupName
        The name of the Resource Group containing the workspace
        .PARAMETER SubscriptionId
        The name of the Azure subscription containing the resource group. If not supplied, uses the subscription if from the
        current Az Context
        .PARAMETER SigmaBackend
        The name of the sigma backend to use. Defaults to 'kusto' which is the only supported option presently.
        .PARAMETER SigmaPipeline
        The name of the sigma pipeline to use. Defaults to 'microsoft_xdr' which is the only supported option presently.
        .PARAMETER SourceUrl
        The source URL link if any related to the source name. Will be displayed in the rule properties.

        .EXAMPLE
        PS> New-AzSentinelContentTemplateFromSigmaRule -Path '.\sigma\rules\windows\registry\rule.yaml' `
            -WorkspaceName sentinel -ResourceGroupName sentinel
        The example above will add a template from the specified file in the supplied workspace using the current Az Context
        .EXAMPLE
        PS> Get-ChildItem .\sigma\rules\windows\process_creation | foreach {
            New-AzSentinelContentTemplateFromSigmaRule -File $_ -WorkspaceName sentinel -ResourceGroupName sentinel
        }
        The example above will add all applicable rules from the specified directory.
    #>
    [CmdletBinding(DefaultParameterSetName='ByPathString')]
    param (
        # Parameter help description
        [Parameter(Mandatory, ParameterSetName='ByFileObject')]
        [System.IO.FileInfo]
        $File,
        # The path under which the sigma yaml files exist, or the path to a single yaml file
        [Parameter(Mandatory, ParameterSetName='ByPathString')]
        [string]
        $Path,
        # The Sentinel Workspace name
        [Parameter(Mandatory)]
        [string]
        $WorkspaceName,
        # The Azure Resource Group the workspace is in
        [Parameter(Mandatory)]
        [string]
        $ResourceGroupName,
        # Subscription GUID. If not supplied, uses the current Az Context
        [Parameter()]
        [string]
        $SubscriptionId,
        # The sigma backend to use. Currently only supports kusto
        [Parameter()]
        [string]
        $SigmaBackend = "kusto",
        # The backend pipeline to use. Currently only supports microsoft_xdr
        [Parameter()]
        [string]
        $SigmaPipeline = "microsoft_xdr",
        # The source name displayed in the list of rule templates in Sentinel. EG: SigmaHQ
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
    $Token = Get-AzAccessToken -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($null -eq $Token -or $Token.ExpiresOn -lt (Get-Date)) {
        Write-Warning "Access token is null or expired. Please log in with Connect-AzAccount"
        Throw "Not logged in"
    }
    if ([string]::IsNullOrEmpty($SubscriptionId)) {
        try {
            $SubscriptionId = (Get-AzContext).Subscription.Id
            Write-Verbose "Using subscription ID: $SubscriptionId"
        }
        catch {
            Throw "Unable to determine Subscription Id from Context. Please supply a valid subscription"
        }
    } else {
        try {
            $context = Set-AzContext -Subscription $SubscriptionId
            Write-Verbose $context
        }
        catch {
            Throw "The supplied subscription ID is not a valid subscription for the currently logged in user"
        }
    }
    $uriStem = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups"
    $uriStem += "/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces"
    $uriStem += "/$WorkspaceName/providers/Microsoft.SecurityInsights"
    $headers = @{Authorization="Bearer $($Token.Token)"}
    #endregion

    #region main
    # Get all existing detection rules
    try {
        $CurrentTemplates = Invoke-RestMethod -Method GET -Uri ($uriStem + "/contentTemplates?api-version=2024-03-01") `
            -Headers $headers
    }
    catch {
        Throw "Failed to get existing templates. $_"
    }

    # if the Path variable was supplied, then get a handle on the file.
    if (-not [string]::IsNullOrEmpty($Path)) {
        try {
            $File = Get-Item $Path -ErrorAction:Stop
            Write-Verbose "Got handle on $($File.Name)"
        }
        catch {
            Throw "Failed to get file. $_"
        }
    }

    # Assume the sigma rule is already present and doesn't need updating
    $addRuleToSentinel = $false

    # Convert file contents to YAML
    try {
        $yaml = ConvertFrom-Yaml (Get-Content $File -raw -ErrorAction Stop) -ErrorAction Stop
        Write-Verbose "Converted $($File.Name) to YAML"
    }
    catch {
        Throw "Failed to convert YAML to object. $_"
    }

    # Only process the rules types applicable to the kusto/microsoft_xdr backend
    if ($yaml.logsource.product -eq "windows" -and
        $supportedCategories -contains $yaml.logsource.category
    ) {
        Write-Verbose "$($File.Name) is supported by sigma engine. Processing"

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
            $query = sigma.exe convert -t $SigmaBackend -p $SigmaPipeline -f default $File.FullName
            if ($null -ne $query)
            {
                Write-Verbose "Kusto query successfully extracted from sigma rule:`n$query"
                $query = $query -join "`n"
                $severity = New-Severity -SigmaYaml $yaml
                $description = New-Description -SigmaYaml $yaml
                $tactics = Read-Tactics -SigmaYaml $yaml
                $techniques = Read-Techniques -SigmaYaml $yaml

                # Process items which are specific to the chosen sigma backend. Specifically the entity mapping and the data sources
                $table = ($query -split '\|')[0].Trim()
                switch ($SigmaPipeline) {
                    'microsoft_xdr' {
                        Write-Verbose "Processing for microsoft_xdr pipeline"
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

                $armTemplate = Build-AzSentinelAlertRuleTemplateArmDocument @ArmParams
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
    }
    else
    {
        Write-Warning "$($File.Name) is NOT supported by sigma engine. Unsupported category is $($yaml.logsource.category)"
    }
    #endregion main
}