# Execute test suite

. .\testUtils.ps1

$testPath = ".\dummyTestSuite"
$testCasesPath = "$testCasesBasePath\testCases"

function Invoke-Test {
    param (
        [string]$FileIn,
        [string]$KeySize,
        [string]$Mode
    )

    $key = $defaultKeys[$KeySize]
    $iv = $defaultIv
    $basePlain = "$testCasesPath\$FileIn"
    $baseEncrypted = "$testCasesPath\$FileIn.$KeySize.$Mode"
    $fileEncrypted = "$testPath\$FileIn.$KeySize.$Mode"
    $fileDecrypted = "$testPath\$FileIn"

    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $iv -FileIn $basePlain -FileOut $fileEncrypted -Decrypt $false -NoPadding $false | Out-Null
    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $iv -FileIn $fileEncrypted -FileOut $fileDecrypted -Decrypt $true -NoPadding $false | Out-Null

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
foreach ($file in $defaultFiles) {
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
