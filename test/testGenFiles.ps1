# Generate test files

. .\testUtils.ps1

$testCasesPath = "$testCasesBasePath\testCases"

$files = "lt1block", "eq1block", "gt1block", "3block"
$iv = "000102030405060708090a0b0c0d0e0f"

function New-Test-Files {
    param (
        [string]$FileIn,
        [string]$KeySize,
        [string]$Mode
    )

    $key = $defaultKeys[$KeySize]
    $iv = $defaultIv
    $FileIn = "$testCasesPath\$FileIn"
    $fileOut = "$FileIn.$KeySize.$Mode"

    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $iv -FileIn $FileIn -FileOut $fileOut -Decrypt $false -NoPadding $false | Out-Null
}

foreach ($file in $defaultFiles) {
    foreach ($keySize in $keySizes) {
        foreach ($mode in $modes) {
            New-Test-Files -FileIn $file -KeySize $keySize -Mode $mode
        }
    }
}
