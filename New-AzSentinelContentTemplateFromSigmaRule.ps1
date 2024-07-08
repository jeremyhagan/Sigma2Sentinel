<# --------------------------------------------------------------------------------------------------------------------------
Author:     Jeremy Hagan
Date:       2024-02-27
Version:    1.0
Purpose:    Parse a directory of sigma rules and create Sentinel Detection Rule (analytics) Template from the sigma rules.

Chlog:      
            2024-05-13: Add a check to ensure that the sigma cli and backend actually 
            returns a query
            2024-05-16: Fix issues:
                - Add switch to ConvertTo-Json to handle unicode characters
                - Add requires PowerShell core due to above
                - Fix incorrect field name in entity mapping
                - Parameterise Source name and URL
-----------------------------------------------------------------------------------------------------------------------------
#>
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

#region local functions
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
