# Generate test files

. .\testUtils.ps1

function New-Test-Files {
    param (
        [string]$FileIn,
        [string]$KeySize,
        [string]$Mode
    )

    $key = $keys[$KeySize]
    $iv = $ivs[$KeySize]
    $FileIn = "$testCasesPath\$FileIn"
    $fileOut = "$FileIn.$KeySize.$Mode"

    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $iv -FileIn $FileIn -FileOut $fileOut -Decrypt $false | Out-Null
}

foreach ($file in $files) {
    foreach ($keySize in $keySizes) {
        foreach ($mode in $modes) {
            New-Test-Files -FileIn $file -KeySize $keySize -Mode $mode
        }
    }
}
