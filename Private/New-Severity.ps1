function New-Severity {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    # The sigma spec lists severities of critical, high, medium, low and informational, but the Analytic Rule accepts only
    # High, Medium, Low, and Informational. The below code sets both critical and high to High and defaults to Ucasing the
    # first letter otherwise. If sigma changes their spec and these no longer align then the Severity of the rule will be
    # listed as Unknown in the Sentinel template and the user can chose something when they enable it.
    switch ($yaml.level)
    {
        'high'
        {
            $severity = "High"
        }
        'critical'
        {
            $severity = "High"
        }
        Default
        {
            $severity = ConvertTo-PascalCase $yaml.level
        }
    }
    return $severity
}
