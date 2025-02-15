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
    $query += "`n`tEntityHost_DnsDomain = strcat_array((array_slice(split(DeviceName, '.'), 1, -1)), '.'),"
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
            $query += (
                "`n`tRegistryValueName = iff(isnotempty(RegistryValueName), RegistryValueName, PreviousRegistryValueName),"
            )
            $query += (
                "`n`tRegistryValueData = iff(isnotempty(RegistryValueData), RegistryValueData, PreviousRegistryValueData)"
            )
            $query += "`n| extend EntityRegistryKey_Hive = tostring(split(RegistryKey, '\\')[0]),"
            $query += "`n`tEntityRegistryKey_Key = strcat_array((array_slice(split(RegistryKey, '\\'), 1, -1)), '\\'),"
            $query += "`n`tEntityRegistryValue_Name = RegistryValueName,"
            $query += "`n`tEntityRegistryValue_Value = RegistryValueData"
        }
        Default{}
    }
    return $query
}
