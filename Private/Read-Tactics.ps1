function Read-Tactics {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    $mitreAttackTacticsMapping = @{
        'collection'                  = 'Collection';
        'command-and-control'         = 'CommandAndControl';
        'credential-access'           = 'CredentialAccess';
        'defense-evasion'             = 'DefenseEvasion';
        'discover'                    = 'Discovery';
        'execution'                   = 'Execution';
        'exfiltration'                = 'Exfiltration';
        'impact'                      = 'Impact';
        'impair-process-control'      = 'ImpairProcessControl';
        'inhibit-response-function'   = 'InhibitResponseFunction';
        'initial-access'              = 'InitialAccess';
        'lateral-movement'            = 'LateralMovement';
        'persistence'                 = 'Persistence';
        'pre-attack'                  = 'PreAttack';
        'privilege-escalation'        = 'PrivilegeEscalation';
        'reconnaissance'              = 'Reconnaissance';
        'resource-development'        = 'ResourceDevelopment'
    }
    $tactics = @()
    [array]$mitreTags = $SigmaYaml.tags | Where-Object {$_ -match "^attack\."}
    foreach ($tag in $mitreTags) {
        $tagArray = $tag -split '\.'
        if ($mitreAttackTacticsMapping.Keys -contains $tagArray[1]) {
            $tactics += ConvertTo-PascalCase $mitreAttackTacticsMapping[$($tagArray[1])]
        }
    }
    return $tactics
}
