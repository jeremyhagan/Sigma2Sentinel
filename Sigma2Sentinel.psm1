<# --------------------------------------------------------------------------------------------------------------------------
Author:     Jeremy Hagan
Date:       2024-02-27
Version:    1.1.0
Purpose:    Create a Sentinel Detection Rule (analytics) Templates from a sigma rule.

Chlog:      
    2024-11-10: Update for dependecy changes
        - Microsoft Defender 365 backend breaking change. Name changed to Kusto and Microsoft 365 Defender moved to be a
          pipeline of Kusto. Future pipelines appear to be in the works to support Windows Audit Logs.
        - Sigma specification changed for MITRE ATT&CK Tactics. Underscores replaced with dashes.
    2024-05-16: Fix issues:
        - Add switch to ConvertTo-Json to handle unicode characters
        - Add requires PowerShell core due to above
        - Fix incorrect field name in entity mapping
        - Parameterise Source name and URL
    2024-05-13: Add a check to ensure that the sigma cli and backend actually 
    returns a query
-----------------------------------------------------------------------------------------------------------------------------
#>
#region Module Variables

#endregion Module Variables

# Dot source all public functions
Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 | ForEach-Object { . $_.FullName }

# Dot source all private functions
Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 | ForEach-Object { . $_.FullName }