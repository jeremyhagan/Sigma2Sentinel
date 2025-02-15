function ConvertTo-PascalCase {
    [CmdletBinding()]
    param (
        # String to capitalise. Each word will be capitalised, space delimited
        [Parameter(Mandatory)]
        [string]
        $InputString
    )
    $Temp = @()
    foreach ($word in ($InputString -split " "))
    {
        $Temp += $word.Substring(0,1).toupper() + $word.Substring(1,$word.length - 1)
    }
    $outputString = $Temp -join " "
    return $outputString
}
