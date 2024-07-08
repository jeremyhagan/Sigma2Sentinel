# Sigma2Sentinel

## Introduction
This script imports Sigma rules into Sentinel as Analytic Rule Templates. For the detections to be useful you must be using Microsoft Defender XDR, with your devices already onboarded to defender. You should also have installed and enabled the [Microsoft Defender XDR Data Collector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-xdr) in your Sentinel instance and be collecting data from the Device* tables.

## Features
Creates Microsoft Sentinel analytic rule templates from sigma rules.  
Adds entities to the analytic rule template to allow you to quickly onboard the template into a rule.  
Supports the following sigma [logsource](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#log-source) categories, as supported by the microsof365defender sigma backend:
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

## Requirements
Run on a host with the following installed
- Modules: [powershell-yaml](https://github.com/cloudbase/powershell-yaml), [Az.SecurityInsights](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/?view=azps-12.0.0)
- [Python](https://www.python.org/downloads/)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
- [The microsoft365defender sigma-cli backend](https://github.com/AttackIQ/pySigma-backend-microsoft365defender)
- a current logged in session (connect-azaccount)
- a directory with sigma rules (clone of https://github.com/SigmaHQ/sigma)
- write access to the target Sentinel workspace

## Setup
1. Clone the SigmaHQ repo, or otherwise prepare a folder with Sigma YAML files in it
2. Install a supported version of Python
3. Install the sigma-cli package `python -m pip install sigma-cli`
4. Install the microsoft365defender sigma backend `sigma plugin install microsoft365defender`
5. Install the required modules listed above

## Entities
Sentinel alerts include properties called [Entities](https://learn.microsoft.com/en-us/azure/sentinel/entities) which are used to find other events related to field in the event data which triggered the alert. Creating entities in an analytic rule is possibly the most tedious and time consuming part of creating the rule. Entities have a number of types, each of which can have one or more identifiers. For example, the entity of IP has an identifier of Address. Other entity types are more complex, such as an Account or Host, which have many more identifiers. See the [Entitity Type Reference](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference) for a full list.  
An alert can contain up to NN entities and each entity can be comprised of up to 3 identifiers. This script adds all available entity types and all available identifiers to each entity as it is impossible to tell which entity is important any given detection. When you onboard a rule template into a rule, you need to remove the entities/identifiers which are not needed before you can save it.

### Identifier field names
Some identifiers need to be extracted from within existing columns and others do not. To provide a consistent method for creating entities, every Entity created is supported by dedciated columns which are added to the KQL query produced by the back end. These columns follow a consisten naming convention as follows:  
**Entity***EntityType*_*Identifier*\[\_*Instance*\]  
Where:  
- **Entity**: is a literal keyword indicating the column is for the purpose of entity mappying. This allows for easy reference using the project KQL statement. E.G., project-away Entity*  
- *EntityType*: is the entity type as per the [Entitity Type Reference](https://learn.microsoft.com/en-us/azure/sentinel/)  
- *Identifier*: is the entitiy identifier as per the [Entitity Type Reference](https://learn.microsoft.com/en-us/azure/sentinel/)  
- \[\_*Instance*\]: is an optional suffix for distinguishing cases where there are multiple entities of the same type.  

**Examples**
- EntityRegistryKey_Hive: The Hive identifier of a Registry Key entity type
- EntityProcess_CommandLine: The Command Line identifier of a Process entity type  
- EntityIP_Address_Remote: The Address identifier of an IP entity type with an instance suffix "Remote"  
- EntityIP_Address_Local: The Address identifier of an IP entity type with an instance suffix "Local"  

## To-do
- Turn into a module
- Work out licensing issues regarding Sigma rule use (https://github.com/SigmaHQ/Detection-Rule-License)
- Work out how to link the Sentinel Support URL back to the repo link in SigmaHQ
- Handle the potential for a GUID clash

