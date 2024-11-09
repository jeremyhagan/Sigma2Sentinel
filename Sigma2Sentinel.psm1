<# --------------------------------------------------------------------------------------------------------------------------
Author:     Jeremy Hagan
Date:       2024-02-27
Version:    1.0.2
Purpose:    Parse a directory of sigma rules and create Sentinel Detection Rule (analytics) Templates from the sigma rules.

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
#region Module Variables

#endregion Module Variables

# Dot source all public functions
Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 | ForEach-Object { . $_.FullName }

# Dot source all private functions
Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 | ForEach-Object { . $_.FullName }