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
}

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
        # The author of the rule. A hash containing any of email, link, name. EG: @{email=me@exmplae.com;link="https://my.blog.com";name="Joe Bloggs"}
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

function Build-AzSetinelAlertRuleTemplateArmDocument {
    <#
    Build an ARM template to be passed with the Content Template - Install REST API.
    For full specs of the REST API see: 
    https://learn.microsoft.com/en-us/rest/api/securityinsights/content-template/install?view=rest-securityinsights-2023-11-01&tabs=HTTP
    For full specs of the ARM template see: 
    https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules?pivots=deployment-language-arm-template
    https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/metadata?pivots=deployment-language-arm-template
    NOTE: This builder only supports Scheduled Alert Rules, not NRT since the Schema differs

    Returns: A hashtable to be used by other functions
    #>
    [CmdletBinding()]
    param(
        # The content version and the resulting template version. if this ARM template updates any content of an existing rule, be sure to update the version number
        [Parameter(Mandatory)]
        [string]
        $Version,
        # The name of the resource, this will always be a GUID and should always be the same GUID if updating a rule. Use the same GUID passed with the template to the REST API.
        [Parameter(Mandatory)]
        [guid]
        $Name,
        # The rule description
        [Parameter(Mandatory)]
        [string]
        $Description,
        # The display name of the rule. This should also match the display name passed with the template to the REST API.
        [Parameter(Mandatory)]
        [string]
        $DisplayName,
        # The KQL query for the rule.
        [Parameter(Mandatory)]
        [string]
        $Query,
        # The severity level of the resulting Alert
        [Parameter(Mandatory)]
        [ValidateSet(
            'High',
            'Informational',
            'Low',
            'Medium'
        )]
        [string]
        $Severity,
        # Source type of the content. Must always contain 'kind' with limited values supported 
        [Parameter(Mandatory)]
        [hashtable]
        $SourceType,
        # The MITRE ATT&CK Tactics applicable to the detection
        [Parameter()]
        [array]
        $Tactics,
        # The MITRE ATT&CK Techniques appliable to the detection. Note: Subtechniques are not supported: EG T1234, NOT T1234.001
        [Parameter()]
        [array]
        $Techniques,
        # Entity Mapping as relates to the data type. These should be built outside the function and passed in as an array
        [Parameter()]
        [array]
        $EntityMappings,
        # The data conector and data type required by the query. I have not found a good source of these. Best to base them on existing templates which you can view by running Get-AzSentinelAlertRuleTemplate
        [Parameter()]
        [array]
        $RequiredDataConnectors,
        # The original author of the detection rule. This is important for attribution (minimum is name). EG: @{email="jeremy.hagan@acma.gov.au";name="Jeremy Hagan"}
        [Parameter()]
        [hashtable]
        $Author,
        # The details for support. Should reference the original URL where the detection rule came from. EG: @{tier="Community"; name="Community"; link="https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_add/registry_add_malware_netwire.yml"}
        [Parameter()]
        [hashtable]
        $Support
    )
    #region variables
    $schema = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    $kind = "Scheduled"
    $queryFrequency = "P1D"
    $queryPeriod = "P1D"
    #endregion

    #region main
    try {
        $ArmTemplate = @{
            "`$schema"          = $schema
            "contentVersion"    = $Version
            "resources"         = @(
                @{
                    "type"          = "Microsoft.SecurityInsights/AlertRuleTemplates"
                    "apiVersion"    = "2022-04-01-preview"
                    "name"          = $Name
                    "kind"          = $kind
                    "properties" = @{
                        "description"           = $Description
                        "displayName"           = $DisplayName
                        "enabled"               = $false
                        "query"                 = $Query
                        "queryFrequency"        = $queryFrequency
                        "queryPeriod"           = $queryPeriod
                        "severity"              = $Severity
                        "status"                = "available"
                        "suppressionDuration"   = "PT1H"
                        "suppressionEnabled"    = $false
                        "triggerOperator"       = "GreaterThan"
                        "triggerThreshold"      = 0
                    }
                }
                @{
                    "type"          = "Microsoft.OperationalInsights/workspaces/providers/metadata"
                    "apiVersion"    = "2021-03-01-preview"
                    "properties"    = @{
                        "description"   = $Description
                        "version"       = $Version
                        "contentId"     = $Name
                        "parentId"      = $Name
                        "source"        = $SourceType
                        "kind"          = $kind
                    }
                }
            )
        }
        if ($null -ne $Tactics) {$ArmTemplate.resources[0].properties.Add("tactics", $Tactics)}
        if ($null -ne $Techniques) {$ArmTemplate.resources[0].properties.Add("techniques", $Techniques)}
        if ($null -ne $EntityMappings) {$ArmTemplate.resources[0].properties.Add("entityMappings", $EntityMappings)}
        if ($null -ne $RequiredDataConnectors) {$ArmTemplate.resources[0].properties.Add("requiredDataConnectors", $RequiredDataConnectors)}
        if ($null -ne $Author) {$ArmTemplate.resources[1].properties.Add("author", $Author)}
        if ($null -ne $Support) {$ArmTemplate.resources[1].properties.Add("support", $Support)}
        if ($null -ne $Tactics) {$ArmTemplate.resources[1].properties.Add("tactics", $Tactics)}
        if ($null -ne $Techniques) {$ArmTemplate.resources[1].properties.Add("techniques", $Techniques)}
    }
    catch {
        $exception = $_.Exception
        Write-Error "Caught exception: $exception"
        throw $exception
    }
    return $ArmTemplate
    #endregion
}
function ConvertTo-PascalCase {
    [CmdletBinding()]
    param (
        # String to capitalise. Each word will be capitalised, space delimited
        [Parameter(Mandatory)]
        [string]
        $InputString
    )
    $Temp = @()
    foreach ($word in ($InputString -split " "))
    {
        $Temp += $word.Substring(0,1).toupper() + $word.Substring(1,$word.length - 1)
    }
    $outputString = $Temp -join " "
    return $outputString
}

function Update-QueryWithEntityMappingColumns {
    [CmdletBinding()]
    param (
        # The table name to base the new columns on. E.g., DeviceProcessEvents
        [Parameter(Mandatory)]
        [string]
        $TableName
    )
    # Generate columns which are common to all tables
    $query = "`n| extend EntityHost_HostName = tostring(split(DeviceName, '.')[0]),"
    $query += "`n`tEntityHost_DnsDoman = strcat_array((array_slice(split(DeviceName, '.'), 1, -1)), '.'),"
    $query += "`n`tEntityAccount_Name = InitiatingProcessAccountName,"
    $query += "`n`tEntityAccount_NTDomain = InitiatingProcessAccountDomain,"
    $query += "`n`tEntityAccount_UpnSuffix = tostring(split(InitiatingProcessAccountUpn, '@')[1]),"
    $query += "`n`tEntityAccount_DnsDomain = tostring(split(InitiatingProcessAccountUpn, '@')[1]),"
    $query += "`n`tEntityAccount_Sid = InitiatingProcessAccountSid,"
    $query += "`n`tEntityAccount_ObjectGuid = InitiatingProcessAccountObjectId,"
    $query += "`n`tEntityFile_Name_Initiating = InitiatingProcessFileName,"
    $query += "`n`tEntityFile_Directory_Initiating = InitiatingProcessFolderPath,"
    $query += "`n`tEntityFileHash_Algorithm_Initiating = 'SHA256',"
    $query += "`n`tEntityFileHash_Value_Initiating = InitiatingProcessSHA256,"
    $query += "`n`tEntityProcess_ProcessId = InitiatingProcessId,"
    $query += "`n`tEntityProcess_CommandLine = InitiatingProcessCommandLine,"
    $query += "`n`tEntityProcess_ElevationToken = InitiatingProcessTokenElevation,"
    $query += "`n`tEntityProcess_CreationTimeUtc = InitiatingProcessParentCreationTime"

    switch ($TableName) {
        'DeviceEvents' {
            $query += "`n| extend EntityIP_Address_Remote = RemoteIP,"
            $query += "`n`tEntityIP_Address_Local = LocalIP,"
            $query += "`n`tEntityFile_Name = FileName,"
            $query += "`n`tEntityFile_Directory = FolderPath,"
            $query += "`n`tEntityFileHash_Algorithm = 'SHA256',"
            $query += "`n`tEntityFileHash_Value = SHA256"
        }
        'DeviceFileEvents' {
            $query += "`n| extend EntityFile_Name = FileName,"
            $query += "`n`tEntityFile_Directory = FolderPath,"
            $query += "`n`tEntityFileHash_Algorithm = 'SHA256',"
            $query += "`n`tEntityFileHash_Value = SHA256"
        }
        'DeviceImageLoadEvents' {
            $query += "`n| extend EntityFile_Name = FileName,"
            $query += "`n`tEntityFile_Directory = FolderPath,"
            $query += "`n`tEntityFileHash_Algorithm = 'SHA256',"
            $query += "`n`tEntityFileHash_Value = SHA256"
        }
        'DeviceNetworkEvents' {
            $query += "`n| extend EntityIP_Address_Remote = RemoteIP,"
            $query += "`n`tEntityIP_Address_Local = LocalIP,"
            $query += "`n`tEntityUrl_Url = RemoteUrl"
        }
        'DeviceProcessEvents' {
            $query += "`n| extend EntityFile_Name = FileName,"
            $query += "`n`tEntityFile_Directory = FolderPath,"
            $query += "`n`tEntityFileHash_Algorithm = 'SHA256',"
            $query += "`n`tEntityFileHash_Value = SHA256"
            # Modify the Process Entity fields created in the common section.
            $query = $query.Replace("EntityProcess_ProcessId = InitiatingProcessId", "EntityProcess_ProcessId = ProcessId")
            $query = $query.Replace("EntityProcess_CommandLine = InitiatingProcessCommandLine", 
                "EntityProcess_CommandLine = ProcessCommandLine")
            $query = $query.Replace("EntityProcess_ElevationToken = InitiatingProcessTokenElevation", 
                "EntityProcess_ElevationToken = ProcessTokenElevation")
            $query = $query.Replace("EntityProcess_CreationTimeUtc = InitiatingProcessParentCreationTime", 
                "EntityProcess_CreationTimeUtc = ProcessCreationTime")
        }
        'DeviceRegistryEvents' {
            $query += "`n| extend RegistryKey = iff(isnotempty(RegistryKey), RegistryKey, PreviousRegistryKey),"
            $query += "`n`tRegistryValueName = iff(isnotempty(RegistryValueName), RegistryValueName, PreviousRegistryValueName),"
            $query += "`n`tRegistryValueData = iff(isnotempty(RegistryValueData), RegistryValueData, PreviousRegistryValueData)"
            $query += "`n| extend EntityRegistryKey_Hive = tostring(split(RegistryKey, '\\')[0]),"
            $query += "`n`tEntityRegistryKey_Key = strcat_array((array_slice(split(RegistryKey, '\\'), 1, -1)), '\\'),"
            $query += "`n`tEntityRegistryValue_Name = RegistryValueName,"
            $query += "`n`tEntityRegistryValue_Value = RegistryValueData"
        }
        Default{}
    }
    return $query
}

function New-EntityMappings {
    [CmdletBinding()]
    param (
        # The table name to base the new columns on. E.g., DeviceProcessEvents
        [Parameter(Mandatory)]
        [string]
        $TableName
    )
    #Entity Mappings common to all tables
    $entityMappings = @(
        @{
            entityType      = 'Host';
            fieldMappings   = @(
                @{
                    columnName = 'EntityHost_HostName';
                    identifier = 'HostName';
                },
                @{
                    columnName = 'EntityHost_DnsDoman';
                    identifier = 'DnsDomain';
                }
            )
        }
        @{
            entityType      = 'Account';
            fieldMappings   = @(
                @{
                    columnName = 'EntityAccount_Name';
                    identifier = 'Name';
                },
                @{
                    columnName = 'EntityAccount_NTDomain';
                    identifier = 'NTDomain';
                },
                @{
                    columnName = 'EntityAccount_UpnSuffix';
                    identifier = 'UPNSuffix';
                }
                @{
                    columnName = 'EntityAccount_DnsDomain';
                    identifier = 'DnsDomain';
                },
                @{
                    columnName = 'EntityAccount_Sid';
                    identifier = 'Sid';
                },
                @{
                    columnName = 'EntityAccount_ObjectGuid';
                    identifier = 'ObjectGuid';
                }
            )
        }
        @{
            entityType      = 'File';
            fieldMappings   = @(
                @{
                    columnName = 'EntityFile_Name_Initiating';
                    identifier = 'Name';
                },
                @{
                    columnName = 'EntityFile_Directory_Initiating';
                    identifier = 'Directory';
                }
            )
        }
        @{
            entityType      = 'FileHash';
            fieldMappings   = @(
                @{
                    columnName = 'EntityFileHash_Algorithm_Initiating';
                    identifier = 'Algorithm';
                },
                @{
                    columnName = 'EntityFileHash_Value_Initiating';
                    identifier = 'Value';
                }
            )
        }
        @{
            entityType      = 'Process';
            fieldMappings   = @(
                @{
                    columnName = 'EntityProcess_ProcessId';
                    identifier = 'ProcessId';
                },
                @{
                    columnName = 'EntityProcess_CommandLine';
                    identifier = 'CommandLine';
                },
                @{
                    columnName = 'EntityProcess_ElevationToken';
                    identifier = 'ElevationToken';
                },
                @{
                    columnName = 'EntityProcess_CreationTimeUtc';
                    identifier = 'CreationTimeUtc';
                }
            )
        }
    )
    # Add additional mappings deneding on the table type
    switch ($TableName) {
        'DeviceEvents' {
            $entityMappings += @{
                entityType = 'IP';
                fieldMappings = @(
                    @{
                        columnName = 'EntityIP_Address_Remote';
                        identifier = 'Address';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'IP';
                fieldMappings = @(
                    @{
                        columnName = 'EntityIP_Address_Local';
                        identifier = 'Address';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'File';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFile_Name';
                        identifier = 'Name';
                    },
                    @{
                        columnName = 'EntityFile_Directory';
                        identifier = 'Directory';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'FileHash';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFileHash_Algorithm';
                        identifier = 'Algorithm';
                    },
                    @{
                        columnName = 'EntityFileHash_Value';
                        identifier = 'Value';
                    }
                )
            }
        }
        'DeviceFileEvents' {
            $entityMappings += @{
                entityType = 'File';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFile_Name';
                        identifier = 'Name';
                    },
                    @{
                        columnName = 'EntityFile_Directory';
                        identifier = 'Directory';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'FileHash';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFileHash_Algorithm';
                        identifier = 'Algorithm';
                    },
                    @{
                        columnName = 'EntityFileHash_Value';
                        identifier = 'Value';
                    }
                )
            }
        }
        'DeviceImageLoadEvents' {
            $entityMappings += @{
                entityType = 'File';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFile_Name';
                        identifier = 'Name';
                    },
                    @{
                        columnName = 'EntityFile_Directory';
                        identifier = 'Directory';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'FileHash';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFileHash_Algorithm';
                        identifier = 'Algorithm';
                    },
                    @{
                        columnName = 'EntityFileHash_Value';
                        identifier = 'Value';
                    }
                )
            }
        }
        'DeviceNetworkEvents' {
            $entityMappings += @{
                entityType = 'IP';
                fieldMappings = @(
                    @{
                        columnName = 'EntityIP_Address_Remote';
                        identifier = 'Address';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'IP';
                fieldMappings = @(
                    @{
                        columnName = 'EntityIP_Address_Local';
                        identifier = 'Address';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'URL';
                fieldMappings = @(
                    @{
                        columnName = 'EntityUrl_Url';
                        identifier = 'Url';
                    }
                )
            }
        }
        'DeviceProcessEvents' {
            $entityMappings += @{
                entityType = 'File';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFile_Name';
                        identifier = 'Name';
                    },
                    @{
                        columnName = 'EntityFile_Directory';
                        identifier = 'Directory';
                    }
                )
            }
            $entityMappings += @{
                entityType = 'FileHash';
                fieldMappings = @(
                    @{
                        columnName = 'EntityFileHash_Algorithm';
                        identifier = 'Algorithm';
                    },
                    @{
                        columnName = 'EntityFileHash_Value';
                        identifier = 'Value';
                    }
                )
            }
        }
        'DeviceRegistryEvents' {
            $entityMappings += @{
                entityType = 'RegistryValue';
                fieldMappings = @(
                    @{
                        columnName = 'EntityRegistryValue_Name';
                        identifier = 'Name';
                    },
                    @{
                        columnName = 'EntityRegistryValue_Value';
                        identifier = 'Value';
                    }
                )
            }
        }
        Default {}
    }
    return $entityMappings
}

function New-Description {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    $description =  $SigmaYaml.description
    $description += "`n`nReferences:`n$($SigmaYaml.references -join "`n")"
    $description += "`n`nSigma ID: $($yaml.id)"
    $description += "`nSigma Date: $($yaml.date)"
    $description += "`nSigma Status: $($yaml.status)"
    
    # Add details from the falsepositives to the description if they exist
    if ($null -ne $yaml.falsepositives -and $yaml.falsepositives[0] -ne "Unknown")
    {
        $description += "`n`nFalse positives:`n$($yaml.falsepositives)"
    }

    # Extract an CVE information from the tags
    [array]$cveTags = $SigmaYaml.tags | Where-Object {$_ -match "^cve\."}
    foreach ($cve in $cveTags) {
        $cve = $cve.Replace("\.", "-").ToUpper()
        $description += "`n$($cve): https://cve.mitre.org/cgi-bin/cvename.cgi?name=$cve"
    }
    return $description
}

function New-Severity {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    # The sigma spec lists critical, high, medium, low and informational, but the Analytic Rule accepts only
    # High, Medium, Low, and Informational. The below code sets both criticial and high to High and defaults
    # to Ucasing the first letter otherwise. if sigma changes their spec and these no longer align then the
    # Severity of the rule will be listed as Unknown in Sentinel and the user can chose something when they
    # onboard it.
    switch ($yaml.level)
    {
        'high'
        {
            $severity = "High"
        }
        'critical'
        {
            $severity = "High"
        }
        Default
        {
            $severity = ConvertTo-PascalCase $yaml.level
        }
    }
    return $severity
}

function Read-Tactics {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    $mitreAttackTacticsMapping = @{
        collection                  = 'Collection';
        command_and_control         = 'CommandAndControl';
        credential_access           = 'CredentialAccess';
        defense_evasion             = 'DefenseEvasion';
        discover                    = 'Discovery';
        execution                   = 'Execution';
        exfiltration                = 'Exfiltration';
        impact                      = 'Impact';
        impair_process_control      = 'ImpairProcessControl';
        inhibit_response_function   = 'InhibitResponseFunction';
        initial_access              = 'InitialAccess';
        lateral_movement            = 'LateralMovement';
        persistence                 = 'Persistence';
        pre_attack                  = 'PreAttack';
        privilege_escalation        = 'PrivilegeEscalation';
        reconnaissance              = 'Reconnaissance';
        resource_development        = 'ResourceDevelopment'
    }
    $tactics = @()
    [array]$mitreTags = $SigmaYaml.tags | Where-Object {$_ -match "^attack\."}
    foreach ($tag in $mitreTags) {
        $tagArray = $tag -split '\.'
        if ($mitreAttackTacticsMapping.Keys -contains $tagArray[1]) {
            $tactics += ConvertTo-PascalCase $mitreAttackTacticsMapping[$($tagArray[1])]
        }
    }
    return $tactics
}

function Read-Techniques {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    $techniques = @()
    [array]$mitreTags = $SigmaYaml.tags | Where-Object {$_ -match "^attack\."}
    foreach ($tag in $mitreTags) {
        $tagArray = $tag -split '\.'
        if ($tagArray[1] -match '^T\d{4}') {
            $techniques += ConvertTo-PascalCase $tagArray[1]
        }
    }
    return $techniques
}

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