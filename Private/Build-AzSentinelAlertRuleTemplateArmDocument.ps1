function Build-AzSentinelAlertRuleTemplateArmDocument {
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
        # The MITRE ATT&CK Techniques applicable to the detection. Note: Sub-techniques are not supported: EG T1234, NOT T1234.001
        [Parameter()]
        [array]
        $Techniques,
        # Entity Mapping as relates to the data type. These should be built outside the function and passed in as an array
        [Parameter()]
        [array]
        $EntityMappings,
        # The data connector and data type required by the query. I have not found a good source of these. Best to base them on existing templates which you can view by running Get-AzSentinelAlertRuleTemplate
        [Parameter()]
        [array]
        $RequiredDataConnectors,
        # The original author of the detection rule. This is important for attribution (minimum is name). EG: @{email="jeremy.hagan@example.com";name="Jeremy Hagan"}
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
        if ($null -ne $RequiredDataConnectors) {
            $ArmTemplate.resources[0].properties.Add("requiredDataConnectors", $RequiredDataConnectors)
        }
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
