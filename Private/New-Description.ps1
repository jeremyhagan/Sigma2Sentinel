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

    # Add details from the false positives to the description if they exist
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
