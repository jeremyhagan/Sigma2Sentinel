# Sigma2Sentinel PowerShell Module

## Synopsis

The `Sigma2Sentinel` PowerShell module is designed to import Sigma rules into Sentinel as Analytic Rule Templates. For the detections to be useful you must be using Microsoft Defender XDR, with your devices already on-boarded to defender. You should also have installed and enabled the [Microsoft Defender XDR Data Collector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-xdr) in your Sentinel instance and be collecting data from the Device* tables.

## Features

- **Set-AzSentinelContentTemplateFromSigmaRule:** Main function to create Microsoft Sentinel analytic rule templates from sigma rules.  
Adds entities to the analytic rule template to allow you to quickly onboard the template into a rule.  
Supports the following sigma [logsource](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#log-source) categories, as supported by the [microsof365defender](https://sigmahq.io/docs/digging-deeper/backends.html#microsoft365defender) sigma backend:
  - process_creation
  - image_load
  - network_connection
  - file_access
  - file_change
  - file_delete
  - file_event
  - file_rename
  - registry_add
  - registry_delete
  - registry_event
  - registry_set

- **Remove-AzSentinelContentTemplate:** Function to remove analytic rule content template. It is possible to create a malformed template which is invisible in the Sentinel portal. This function will delete a template specified by Display Name (if supplied), or All templates. If neither Display Name or All is specified, a list of templates will be displayed to assist you.

## Dependencies
Run on a host with the following installed
- Modules: [powershell-yaml](https://github.com/cloudbase/powershell-yaml), [Az.SecurityInsights](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/?view=azps-12.0.0), [AzExpression](https://github.com/SimonWahlin/AzExpression)
- [Python](https://www.python.org/downloads/)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
- [The Kusto sigma-cli backend](https://github.com/AttackIQ/pySigma-backend-kusto)
- a current logged in session (Connect-AzAccount)
- a directory with sigma rules (clone of https://github.com/SigmaHQ/sigma)
- write access to the target Sentinel workspace ([Sentinel Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#microsoft-sentinel-contributor))

## Setup
1. Clone the SigmaHQ repo, or otherwise prepare a folder with Sigma YAML files in it
2. Install a supported version of Python (3.8+)
3. Install the sigma-cli package `python -m pip install sigma-cli`
4. Install the microsoft365defender sigma backend `sigma plugin install kusto`
5. Install the required modules listed above

## Entities
Sentinel alerts include properties called [Entities](https://learn.microsoft.com/en-us/azure/sentinel/entities) which are used to find other events related to fields in the event data which triggered the alert. Creating entities in an analytic rule is possibly the most tedious and time consuming part of creating the rule. Entities have a number of types, each of which can have one or more identifiers. For example, the entity of IP has an identifier of Address. Other entity types are more complex, such as an Account or Host, which have many more identifiers. See the [Entity Type Reference](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference) for a full list.  
An alert can contain up to NN entities and each entity can be comprised of up to 3 identifiers. This script adds all available entity types and all available identifiers to each entity as it is impossible to tell which entity is important any given detection. When you onboard a rule template into a rule, you need to remove the entities/identifiers which are not needed before you can save it.

### Identifier field names
Some identifiers need to be extracted from within existing columns and others do not. To provide a consistent method for creating entities, every Entity created is supported by dedicated columns which are added to the KQL query produced by the back end. These columns follow a consistent naming convention as follows:  
**Entity***EntityType*_*Identifier*\[\_*Instance*\]  
Where:  
- **Entity**: is a literal keyword indicating the column is for the purpose of entity mapping. This allows for easy reference using the project KQL statement. E.G., project-away Entity*
- *EntityType*: is the entity type as per the [Entity Type Reference](https://learn.microsoft.com/en-us/azure/sentinel/)  
- *Identifier*: is the entity identifier as per the [Entity Type Reference](https://learn.microsoft.com/en-us/azure/sentinel/)  
- \[\_*Instance*\]: is an optional suffix for distinguishing cases where there are multiple entities of the same type.  

**Examples**
- EntityRegistryKey_Hive: The Hive identifier of a Registry Key entity type
- EntityProcess_CommandLine: The Command Line identifier of a Process entity type  
- EntityIP_Address_Remote: The Address identifier of an IP entity type with an instance suffix "Remote"  
- EntityIP_Address_Local: The Address identifier of an IP entity type with an instance suffix "Local"  

## Usage

### Set-AzSentinelContentTemplateFromSigmaRule

The `Set-AzSentinelContentTemplateFromSigmaRule` function provides the core functionality of the module. You pass either a path to a sigma YAML file, or a File object from Get-ChildItem. It will parse the XML and build a Sentinel Template.

If the rule template doesn't already exist in the Sentinel workspace, it will create it.
If the rule template exists, the function will use the date property of the sigma rule to see if it is updated. Sigma rules don't have version, but rule templates use them to see if the template is updated compared to any analytic rules created from it. This function will increment the Sentinel Template version if the sigma rule is newer when it updates it.
If the date property is unchanged, the function will do nothing.

Properties of the sigma rule used for comparisons are stored in the rule template description.

#### Examples

```powershell
Set-AzSentinelContentTemplateFromSigmaRule -Path '.\sigma\rules\windows\registry\rule.yaml' `
    -WorkspaceName sentinel -ResourceGroupName sentinel
```
The example above will add a template from the specified file in the supplied workspace using the current Az Context
```powershell
Get-ChildItem .\sigma\rules\windows\process_creation | foreach {
    Set-AzSentinelContentTemplateFromSigmaRule -File $_ -WorkspaceName sentinel -ResourceGroupName sentinel
}
```

### Remove-AzSentinelContentTemplate

The `Remove-AzSentinelContentTemplate` allows you to remove any templates created in error. Malformed templates can be created which make all template invisible in the portal. You need to use Graph to remove them. This function allows you to delete a specific template by display name, or All user-defined templates. If no display name is provided, a list of template in the workspace is shown and the user is prompted to select one.

#### Examples
```powershell
Remove-AzSentinelContentTemplate -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" `
    -SubscriptionId "SubscriptionId"
```
The example above will prompt for a rule to delete.

OUTPUT
```
[1]: HackTool - Potential Impacket Lateral Movement Activity
[2]: New Port Forwarding Rule Added Via Netsh.EXE
Please select a rule template to delete:
```
```powershell
Remove-AzSentinelContentTemplate -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" -All
```
The example above will remove all templates. Use `-Confirm:$false` to avoid being prompted
```powershell
Remove-AzSentinelContentTemplate -WorkspaceName "WorkspaceName" -ResourceGroupName "ResourceGroupName" `
    -DisplayName "MyRuleName"
```
The example above will remove the specified rule template if it exists.

## Limitations and known issues
- The module only supports the Kusto sigma backend and the microsoft_xdr pipeline.
- If a sigma rule author doesn't generate a new GUID it is possible to have a GUID clash. In this case the winning rule is the last one written. To fix this, simple generate a new GUID for the rule with the clash.
- The sigma rules in SigmaHQ are covered by the [Detection Rules License](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md). This implementation only complies with the first requirement of the license in that is retains the author of the rule in the Sentinel template description. The URL of the run in the SigmaHQ isn't part of the specification therefore the rules are not self-referential. I haven't worked out how to include the URL in the description yet. Finally, the DRL specifies that the author is included in the output of the detection (at least that is how I read it). I also haven't done that.