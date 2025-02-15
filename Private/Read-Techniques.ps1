function Read-Techniques {
    [CmdletBinding()]
    param (
        # A hashtable containing a valid Sigma rule
        [Parameter(Mandatory)]
        [hashtable]
        $SigmaYaml
    )
    $techniques = @()
    [array]$mitreTags = $SigmaYaml.tags | Where-Object {$_ -match "^attack\."}
    foreach ($tag in $mitreTags) {
        $tagArray = $tag -split '\.'
        if ($tagArray[1] -match '^T\d{4}') {
            $techniques += ConvertTo-PascalCase $tagArray[1]
        }
    }
    return $techniques
}
