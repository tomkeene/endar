Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}

#$exists = Test-RegistryValue -path Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\agent9 -name test
$exists = Test-RegistryValue -path  "HKLM:\SYSTEM\CurrentControlSet\Services\agent9" -name test
if (!$exists) {
    write-output "Registry key does not exist!"
    exit 101
}
Write-Output "Registry key exists..."
exit 0
