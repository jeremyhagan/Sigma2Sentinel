<# --------------------------------------------------------------------------------------------------------------------------
Author:     Jeremy Hagan
Date:       2025-02-02
Version:    1.2.1
Purpose:    Create a Sentinel Detection Rule (analytics) Templates from a sigma rule.

Chang log:
    1.2.1   Move all private functions into individual files
            Fix spelling errors in comments and function names
            Add verbose output to Set-AzSentinelContentTemplateFromSigmaRule
    1.2.0   Change New-AzSentinelContentTemplateFromSigmaRule to Set-AzSentinelContentTemplateFromSigmaRule as a more
            appropriate verb, since the function will create new rule and update an existing one
    1.1.0   Update for dependency changes
                - Microsoft Defender 365 backend breaking change. Name changed to Kusto and Microsoft 365 Defender moved to
                 be a pipeline of Kusto. Future pipelines appear to be in the works to support Windows Audit Logs.
                - Sigma specification changed for MITRE ATT&CK Tactics. Underscores replaced with dashes.
    1.0.2   Fix issues:
                - Add switch to ConvertTo-Json to handle unicode characters
                - Add requires PowerShell core due to above
                - Fix incorrect field name in entity mapping
                - Parameterise Source name and URL
    1.0.1   Add a check to ensure that the sigma cli and backend actually returns a query
-----------------------------------------------------------------------------------------------------------------------------
#>
#region Module Variables

#endregion Module Variables

# Dot source all public functions
Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 | ForEach-Object { . $_.FullName }

# Dot source all private functions
Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 | ForEach-Object { . $_.FullName }