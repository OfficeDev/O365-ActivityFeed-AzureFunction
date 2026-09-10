function New-SitAnalysisScope {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Ids = @(),
        [AllowEmptyCollection()][string[]]$Names = @()
    )

    $idSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $nameSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($Ids)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) { [void]$idSet.Add($id.Trim()) }
    }
    foreach ($name in @($Names)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) { [void]$nameSet.Add($name.Trim()) }
    }
    if ($idSet.Count -eq 0 -and $nameSet.Count -eq 0) {
        throw 'The SIT analysis scope is empty. Analysis fails closed.'
    }
    return [pscustomobject]@{ Ids = $idSet; Names = $nameSet }
}

function Test-SensitiveInformationInScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$SensitiveInformation,
        [Parameter(Mandatory)]$Scope
    )

    $id = [string]$SensitiveInformation.SensitiveType
    if ([string]::IsNullOrWhiteSpace($id) -and $SensitiveInformation.PSObject.Properties.Name -contains 'SensitiveInformationTypeId') {
        $id = [string]$SensitiveInformation.SensitiveInformationTypeId
    }
    $name = [string]$SensitiveInformation.SensitiveInformationTypeName
    return ((-not [string]::IsNullOrWhiteSpace($id)) -and $Scope.Ids.Contains($id.Trim())) -or
        ((-not [string]::IsNullOrWhiteSpace($name)) -and $Scope.Names.Contains($name.Trim()))
}
