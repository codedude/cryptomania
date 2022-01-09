# Execute test suite

. .\testUtils.ps1

$testPath = ".\dummy"

function Invoke-Test {
    param (
        [string]$FileIn,
        [string]$KeySize,
        [string]$Mode
    )

    $key = $keys[$KeySize]
    $iv = $ivs[$KeySize]
    $basePlain = "$testCasesPath\$FileIn"
    $baseEncrypted = "$testCasesPath\$FileIn.$KeySize.$Mode"
    $fileEncrypted = "$testPath\$FileIn.$KeySize.$Mode"
    $fileDecrypted = "$testPath\$FileIn"

    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $iv -FileIn $basePlain -FileOut $fileEncrypted -Decrypt $false | Out-Null
    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $iv -FileIn $fileEncrypted -FileOut $fileDecrypted -Decrypt $true | Out-Null

    # Test decrypted file
    $diffPlain = Compare-Object (Get-Content $basePlain) (Get-Content $fileDecrypted)
    $diffEncrypted = Compare-Object (Get-Content $baseEncrypted) (Get-Content $fileEncrypted)

    if ($diffPlain) {
        Write-Host "Diff in plain/decrypted file"
        return $false
    }
    elseif ($diffEncrypted) {
        Write-Host "Diff in encrypted file"
        return $false
    }

    return $true
}

Write-Host "Running tests suite..."

# Create temporary dir to store generated files
New-Item -Force -ItemType "directory" -Path $testPath | Out-Null

# Execute all test combination
foreach ($file in $files) {
    foreach ($keySize in $keySizes) {
        foreach ($mode in $modes) {
            $ret = Invoke-Test -FileIn $file -KeySize $keySize -Mode $mode
            if (!$ret) {
                Write-Host "Error : $file / $keySize-$mode"
            }
        }
    }
}

Write-Host "Tests suite done!"
