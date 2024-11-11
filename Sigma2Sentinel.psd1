@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'Sigma2Sentinel.psm1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Version number of this module.
    ModuleVersion = '1.2.0'

    # ID used to uniquely identify this module
    GUID = '7bcfd6aa-172f-479f-be46-59fd3a9e35e3'

    # Author of this module
    Author = 'Jeremy Hagan'

    # Company or vendor of this module
    CompanyName = 'Jeremy Hagan'

    # Description of the functionality provided by this module
    Description = 'This module imports sigma rules into Sentinel. Sigma is a generic signature format for SIEM systems.'

    # Functions to export from this module
    FunctionsToExport = @(
        'Set-AzSentinelContentTemplateFromSigmaRule',
        'Remove-AzSentinelContentTemplate'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{

    }
}