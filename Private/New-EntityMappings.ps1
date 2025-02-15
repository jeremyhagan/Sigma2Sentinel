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
                    columnName = 'EntityHost_DnsDomain';
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
    # Add additional mappings depending on the table type
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
